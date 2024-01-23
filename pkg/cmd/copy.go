/*
Copyright 2018 The Kubernetes Authors.

            // Check for the next line that contains the resource name
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# based on https://github.com/kubernetes/sample-cli-plugin
*/

package cmd

import (
    "context"
    "fmt"
    "path/filepath"
    // "time"
    "os"
    // "gopkg.in/yaml.v3"
    "strings"
    "regexp"
    // "bytes"
    "github.com/samber/lo"
    // "reflect"

    "github.com/spf13/cobra"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    log "github.com/sirupsen/logrus"

    "k8s.io/client-go/kubernetes"

    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"


    "k8s.io/cli-runtime/pkg/genericclioptions"
    "k8s.io/cli-runtime/pkg/genericiooptions"
    "k8s.io/cli-runtime/pkg/printers"
    "k8s.io/client-go/kubernetes/scheme"

)

var (
    runExample = `
    # with dry-run set to true will create a YAML file of what will be created if set to false
    %[1]s debug-ward -n pod-namespace pod --dry-run=true

    # examples of pod secuirty context values that can be ovewritten
    %[1]s debug-ward -n pod-namespace pod --dry-run=true --psc-runasuser=0 --psc-runasgroup=0 --psc-fsgroup=0 --psc-fsgroupchangepolicy=Always --psc-selinuxoptions="IMPLEMENTE_ME" --psc-seccompprofile="IMPLEMENT_ME" --psc-supplementalgroups="IMPLEMENT_1,IMPLEMENT_2" --psc-sysctls="IMPLEMENT_ME_1,IMPLEMENTE_ME_2"

    # examples of pod constainer secuirty context values that can be ovewritten
    %[1]s debug-ward -n pod-namespace pod --dry-run=true --pcsc-allowprivilegeescalation=true --pcsc-capabilities="IMPLEMENT_ME" --pcsc-privileged=true --pcsc-procmount="IMPLEMENT_ME" --pcsc-readonlyfilesystem=false --pcsc-runasuser=0 --pcsc-runasgroup=0 --pcsc-runasnonroot=false --pcsc-selinuxoptions="IMPLEMENTE_ME" --pcsc-seccompprofile="IMPLEMENT_ME"

    --debug-warn-namespace
    --dry-run
    --psc-runasuser
    --psc-runasgroup
    --psc-fsgroup
    --psc-fsgroupchangepolicy
    --psc-selinuxoptions
    --psc-seccompprofile
    --psc-supplementalgroups
    --psc-sysctls
    --pcsc-allowprivilegeescalation
    --pcsc-capabilities
    --pcsc-priviledges
    --pcsc-procmount
    --pcsc-readonlyfilesystem
    --pcsc-runasuser
    --pcsc-runasgroup
    --pcsc-runasnonroot
    --pcsc-selinuxoptions
    --pcsc-seccompprofile
`

    errNoContext = fmt.Errorf("no context is currently set, use %q to select a new one", "kubectl config use-context <context>")
)

// DebugWardOptions provides information required to update
// the current context on a user's KUBECONFIG
type DebugWardOptions struct {
    configFlags *genericclioptions.ConfigFlags

    resultingContext     *api.Context
    resultingContextName string

    srcK8sClient *kubernetes.Clientset
    dstK8sClient *kubernetes.Clientset

    dryRun bool

    // cluster identification
    debugPodKubeConfig string

    // inside cluster identification
    sourcePodCluster    string
    sourcePodContext    string
    sourcePodUser       string
    sourcePodNamespace  string
    sourcePodName       string

    debugPodNamespace  string
    debugPodNamePrefix string

    debugPodImage      string
    debugPodCommand    string

    // security overrides
    debugPodSecurityContextRunAsUser           *int64
    debugPodSecurityContextRunAsGroup          *int64
    debugPodSecurityContextFSGroup             *int64
    // debugPodSecurityContextFSGroupChangePolicy *corev1.PodFSGroupChangePolicy
    debugPodSecurityContextSELinuxOptions      *corev1.SELinuxOptions
    debugPodSecurityContextSeccompProfile      *corev1.SeccompProfile
    debugPodSecurityContextSupplementalGroups  []int64
    debugPodSecurityContextSysctls             []corev1.Sysctl

    // debugPodContainerSecurityContextAllowPrivilegeEscalation bool
    // debugPodContainerSecurityContextCapabilities             *corev1.Capabilities
    debugPodContainerSecurityContextPrivileged               *bool
    debugPodContainerSecurityContextProcMount                *corev1.ProcMountType
    debugPodContainerSecurityContextReadOnlyRootFilesystem   *bool
    debugPodContainerSecurityContextRunAsUser                *int64
    debugPodContainerSecurityContextRunAsGroup               *int64
    debugPodContainerSecurityContextRunAsNonRoot             *bool
    debugPodContainerSecurityContextSELinuxOptions           *corev1.SELinuxOptions
    debugPodContainerSecurityContextSeccompProfile           *corev1.SeccompProfile

    rawConfig      api.Config
    listNamespaces bool
    args           []string

    genericiooptions.IOStreams
}

// NewDebugWardOptions provides an instance of DebugWardOptions with default values
func NewDebugWardOptions(streams genericiooptions.IOStreams) *DebugWardOptions {
    log.SetFormatter(&log.JSONFormatter{})

    lvl, ok := os.LookupEnv("DEBUG_WARD_LOG_LEVEL")
    if !ok {
        lvl = "info"
    }

    ll, err := log.ParseLevel(lvl)
    if err != nil {
        ll = log.TraceLevel
    }
    log.SetLevel(ll)

    return &DebugWardOptions{
        configFlags: genericclioptions.NewConfigFlags(true),

        dryRun: true,

        sourcePodNamespace: "default",
        sourcePodName: "",

        debugPodNamespace: "debug-ward-tmp",
        debugPodNamePrefix: "dwpt",
        debugPodImage: "ubuntu:22.04",
        debugPodCommand: "bash",

        debugPodSecurityContextRunAsUser: lo.ToPtr(int64(0)),
        debugPodSecurityContextRunAsGroup: lo.ToPtr(int64(0)),
        debugPodSecurityContextFSGroup: lo.ToPtr(int64(0)),
    // debugPodSecurityContextFSGroupChangePolicy: corev1.PodFSGroupChangeAlways,
        debugPodSecurityContextSELinuxOptions: &corev1.SELinuxOptions{},
        debugPodSecurityContextSeccompProfile: &corev1.SeccompProfile{},
        debugPodSecurityContextSupplementalGroups: []int64{},
        debugPodSecurityContextSysctls: []corev1.Sysctl{},

        // debugPodContainerSecurityContextAllowPrivilegeEscalation: &corev1.AllowPrivilegeEscalation{},
        // debugPodContainerSecurityContextCapabilities: corev1.Capabilities,
        debugPodContainerSecurityContextPrivileged: lo.ToPtr(true),
        // debugPodContainerSecurityContextProcMount: &corev1.ProcMountType,
        debugPodContainerSecurityContextReadOnlyRootFilesystem: lo.ToPtr(false),
        debugPodContainerSecurityContextRunAsUser: lo.ToPtr(int64(0)),
        debugPodContainerSecurityContextRunAsGroup: lo.ToPtr(int64(0)),
        debugPodContainerSecurityContextRunAsNonRoot: lo.ToPtr(false),
        debugPodContainerSecurityContextSELinuxOptions: &corev1.SELinuxOptions{},
        debugPodContainerSecurityContextSeccompProfile: &corev1.SeccompProfile{},

        IOStreams: streams,
    }
}

// NewDebugWardPatient provides a cobra command wrapping DebugWardOptions
func NewDebugWardPatient(streams genericiooptions.IOStreams) *cobra.Command {
    log.Trace("Starting NewDebugWardOptions")
    o := NewDebugWardOptions(streams)

    cmd := &cobra.Command{
        Use:          "debug-ward pod-name [flags]",
        Short:        "View or create a copy of a specified pod that can be used for debugging in a new namespace or cluster",
        Example:      fmt.Sprintf(runExample, "kubectl"),
        SilenceUsage: true,
        RunE: func(c *cobra.Command, args []string) error {
            if err := o.Complete(c, args); err != nil {
                return err
            }
            if err := o.Validate(); err != nil {
                return err
            }
            if err := o.Run(); err != nil {
                return err
            }

            return nil
        },
    }

    cmd.Flags().BoolVar(&o.dryRun, "dry-run", o.dryRun, "if true, print the yaml of the pod that is going to be created in the debug-ward namespace; default true")
    cmd.Flags().StringVar(&o.debugPodNamespace, "debug-warn-namespace", o.debugPodNamespace, "if set will use this value as the debug-ward namespace; default ....SPECIFY....")
    o.configFlags.AddFlags(cmd.Flags())

    return cmd
}

// Complete sets all information required for updating the current context
func (o *DebugWardOptions) Complete(cmd *cobra.Command, args []string) error {
    log.Trace("Starting Complete")

    var err error
    o.args = args

    kubeconfigPath := os.Getenv("KUBECONFIG")
    if kubeconfigPath != "" {
        log.Info("KUBECONFIG environment variable is defined:" + kubeconfigPath)
    } else {
        filePath := filepath.Join(homeDir(), ".kube", "config")

        if !fileExists(filePath) {
            log.Fatal("Neither KUBECONFIG environment variable nor default ~/.kube/config file exists:" + filePath)
        }
    }

    // Load kubeconfig
    config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
    if err != nil {
        log.Fatal(err)
    }

    o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
    if err != nil {
        return err
    }

    o.srcK8sClient, err = kubernetes.NewForConfig(config)
    if err != nil {
        log.Fatal("Error creating Kubernetes source client: \n", err)
    }

    o.dryRun, err = cmd.Flags().GetBool("dry-run")
    if err != nil {
        return err
    }
    log.Trace("flag: dry-run set to ", o.dryRun)

    o.debugPodNamespace, err = cmd.Flags().GetString("debug-warn-namespace")
    if err != nil {
        return err
    }
    log.Trace("flag: debug-warn-namespace set to ", o.debugPodNamespace)

    o.sourcePodNamespace, err = cmd.Flags().GetString("namespace")
    if err != nil {
        return err
    }

    // if no namespace argument or flag value was specified, then there
    // is no need to generate a resulting context
    if len(o.sourcePodNamespace) == 0 {
        return nil
    }

    log.Trace("setting context start...")
    o.sourcePodContext, err = cmd.Flags().GetString("context")
    if err != nil {
        return err
    }

    o.sourcePodCluster, err = cmd.Flags().GetString("cluster")
    if err != nil {
        return err
    }

    o.sourcePodUser, err = cmd.Flags().GetString("user")
    if err != nil {
        return err
    }

    currentContext, exists := o.rawConfig.Contexts[o.rawConfig.CurrentContext]
    if !exists {
        return errNoContext
    }

    o.resultingContext = api.NewContext()
    o.resultingContext.Cluster = currentContext.Cluster
    o.resultingContext.AuthInfo = currentContext.AuthInfo

    // if a target context is explicitly provided by the user,
    // use that as our reference for the final, resulting context
    if len(o.sourcePodContext) > 0 {
        o.resultingContextName = o.sourcePodContext
        if userCtx, exists := o.rawConfig.Contexts[o.sourcePodContext]; exists {
            o.resultingContext = userCtx.DeepCopy()
        }
    }

    // override context info with user provided values
    o.resultingContext.Namespace = o.sourcePodNamespace

    if len(o.sourcePodCluster) > 0 {
        o.resultingContext.Cluster = o.sourcePodCluster
    }
    if len(o.sourcePodUser) > 0 {
        o.resultingContext.AuthInfo = o.sourcePodUser
    }

    // generate a unique context name based on its new values if
    // user did not explicitly request a context by name
    if len(o.sourcePodContext) == 0 {
        o.resultingContextName = generateContextName(o.resultingContext)
    }

    // override context info with user provided values
    o.resultingContext.Namespace = o.sourcePodNamespace

    log.Trace("setting context end...")

    return nil
}

func generateContextName(fromContext *api.Context) string {
    log.Trace("Starting generateContextName")
    name := fromContext.Namespace
    if len(fromContext.Cluster) > 0 {
        name = fmt.Sprintf("%s/%s", name, fromContext.Cluster)
    }
    if len(fromContext.AuthInfo) > 0 {
        cleanAuthInfo := strings.Split(fromContext.AuthInfo, "/")[0]
        name = fmt.Sprintf("%s/%s", name, cleanAuthInfo)
    }

    return name
}

func homeDir() string {
    if h := os.Getenv("HOME"); h != "" {
        return h
    }
    return os.Getenv("USERPROFILE")
}

func fileExists(filePath string) bool {
    _, err := os.Stat(filePath)
    return err == nil || !os.IsNotExist(err)
}

// Validate ensures that all required arguments and flag values are provided
func (o *DebugWardOptions) Validate() error {
    log.Trace("Starting Validate")

    if len(o.rawConfig.CurrentContext) == 0 {
        return errNoContext
    }
    if len(o.args) != 1 {
        return fmt.Errorf("provide the name of the pod that will be cloned in the debug-ward")
    }
    if len(o.args) > 1 {
        return fmt.Errorf("too many arguments provided")
    }

    return nil
}

// Run copy of debug pod using the provided options
func (o *DebugWardOptions) Run() error {
    log.Trace("Starting Run")

    o.sourcePodName = o.args[0]
    log.Debug("pod name ", o.sourcePodName)

    log.Trace("Starting Run: get pod")
    pod, err := o.srcK8sClient.CoreV1().Pods(o.sourcePodNamespace).Get(context.TODO(), o.sourcePodName, metav1.GetOptions{})
    if err != nil {
        return err
    }

    log.Trace("Starting Run: get Secrets")
    secrets, err := o.getSecretsFromPod(pod)
    if err != nil {
        return err
    }

    log.Trace("Starting Run: get ConfigMaps")
    configMaps, err := o.getConfigMapsFromPod(pod)
    if err != nil {
        return err
    }

    //
    // cleanup
    //
    podClean := cleanPod(pod)
    configMapsClean := cleanConfigMaps(configMaps)
    secretsClean := cleanSecrets(secrets)

    podTreat := o.treatPod(podClean)
    configMapsTreat := o.treatConfigMaps(configMapsClean)
    secretsTreat := o.treatSecrets(secretsClean)

    // ###################
    // remove secrets/ configMap duplicates to avoid errors during creation
    // ###################
    if o.dryRun == true {
        o.debugWardDryRun(podTreat, configMapsTreat, secretsTreat)
    } else {
        o.debugWardCopy(podTreat, configMapsTreat, secretsTreat)
    }


    return nil
}

func (o *DebugWardOptions) debugWardDryRun(pod *corev1.Pod, configMaps []*corev1.ConfigMap, secrets []*corev1.Secret) error {
    log.Trace("Starting debugWardDryRun")

    printr := printers.NewTypeSetter(scheme.Scheme).ToPrinter(&printers.YAMLPrinter{})

    for _, configMap := range configMaps {
        fmt.Sprintf("\n---")
        err := printr.PrintObj(configMap, os.Stdout)
        if err != nil {
            log.Panic(err)
        }
    }

    for _, secret := range secrets {
        fmt.Sprintf("\n---")
        err := printr.PrintObj(secret, os.Stdout)
        if err != nil {
            log.Panic(err)
        }
    }

    fmt.Sprintf("\n---")
    err := printr.PrintObj(pod, os.Stdout)
    if err != nil {
       log.Panic(err)
    }

    return nil
}

func (o *DebugWardOptions) debugWardCopy(pod *corev1.Pod, configMaps []*corev1.ConfigMap, secrets []*corev1.Secret) error {
    log.Trace("Starting debugWardCopy")

    // printr := printers.NewTypeSetter(scheme.Scheme).ToPrinter(&printers.YAMLPrinter{})

    // var yamlBuffer bytes.Buffer

    for _, configMap := range configMaps {
        // err := printr.PrintObj(configMap, &yamlBuffer)
        // if err != nil {
        //     return err
        // }
	tmpConfigMap, err := o.srcK8sClient.CoreV1().ConfigMaps(o.debugPodNamespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
	log.Debug(tmpConfigMap)
        if err != nil {
            log.Fatal("Error creating ConfigMap: ", err)
        }
        log.Info("ConfigMap created successfully.")
    }

    for _, secret := range secrets {
        // err := printr.PrintObj(secret, &yamlBuffer)
        // if err != nil {
        //     return err
        // }
	tmpSecret, err := o.srcK8sClient.CoreV1().Secrets(o.debugPodNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	log.Debug(tmpSecret)
        // err = o.createResource(o.srcK8sClient, yamlBuffer.Bytes(), "Secret")
        if err != nil {
            log.Fatal("Error creating Secret: ", err)
        }
        log.Info("Secret created successfully.")
    }

    // var podBuffer bytes.Buffer
    // err := printr.PrintObj(pod, &podBuffer)
    // if err != nil {
    //     return err
    // }
    // fmt.Sprintf(podBuffer.String())
    tmpPod, err := o.srcK8sClient.CoreV1().Pods(o.debugPodNamespace).Create(context.TODO(), pod, metav1.CreateOptions{})
    log.Debug(tmpPod)
    // err = o.createResource(o.srcK8sClient, configBuffer.Bytes(), "Pod")
    if err != nil {
        log.Fatal("Error creating Pod: ", err)
    }
    log.Info("Pod created successfully.")

    return nil
}

func (o *DebugWardOptions) getSecretsFromPod(pod *corev1.Pod) ([]*corev1.Secret, error) {
    log.Trace("Starting getSecretsFromPod")
    var secrets []*corev1.Secret

    // Check volumes for secrets
    for _, volume := range pod.Spec.Volumes {
        if volume.Secret != nil {
            secret, err := o.srcK8sClient.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), volume.Secret.SecretName, metav1.GetOptions{})
            if err != nil {
                return nil, err
            }
            secrets = append(secrets, secret)
        }
    }

    // Check environment variables for secrets
    for _, container := range pod.Spec.Containers {
        for _, env := range container.Env {
            if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
                secret, err := o.srcK8sClient.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), env.ValueFrom.SecretKeyRef.Name, metav1.GetOptions{})
                if err != nil {
                    return nil, err
                }
                secrets = append(secrets, secret)
            }
        }
    }

    return secrets, nil
}

func (o *DebugWardOptions) getConfigMapsFromPod(pod *corev1.Pod) ([]*corev1.ConfigMap, error) {
    log.Trace("Starting getConfigMapsFromPod")
    var configMaps []*corev1.ConfigMap

    // Check volumes for config maps
    for _, volume := range pod.Spec.Volumes {
        if volume.ConfigMap != nil {
            configMap, err := o.srcK8sClient.CoreV1().ConfigMaps(pod.Namespace).Get(context.TODO(), volume.ConfigMap.Name, metav1.GetOptions{})
            if err != nil {
                return nil, err
            }
            configMaps = append(configMaps, configMap)
        }
    }

    // Check environment variables for config maps
    for _, container := range pod.Spec.Containers {
        for _, env := range container.Env {
            if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
                configMap, err := o.srcK8sClient.CoreV1().ConfigMaps(pod.Namespace).Get(context.TODO(), env.ValueFrom.ConfigMapKeyRef.Name, metav1.GetOptions{})
                if err != nil {
                    return nil, err
                }
                configMaps = append(configMaps, configMap)
            }
        }
    }

    return configMaps, nil
}

func cleanPod(pod *corev1.Pod) (*corev1.Pod) {
    log.Trace("Starting cleanPod")
    // main fields
    pod.ObjectMeta.CreationTimestamp = metav1.Time{}
    pod.ObjectMeta.ManagedFields = nil
    pod.ObjectMeta.OwnerReferences = nil
    pod.Status = corev1.PodStatus{}

    // meta fields
    pod.ObjectMeta.GenerateName = ""
    pod.ObjectMeta.Namespace = ""
    pod.ObjectMeta.ResourceVersion = ""
    pod.ObjectMeta.UID = ""
    for label := range pod.ObjectMeta.Labels {
        delete(pod.ObjectMeta.Labels, label)
    }

    // spec fields pod
    pod.Spec.DNSPolicy = ""
    pod.Spec.NodeName = ""
    pod.Spec.SchedulerName = ""

    regexVolumeKubeApiAccess, err := regexp.Compile("^kube-api-access-[a-z]{1,16}")
    if err != nil {
        log.Panic("Error compiling regex: %v\n", err)
    }

    volumesRemoved := []string{}
    for _, volume := range pod.Spec.Volumes {
        log.Trace("checking if removal is applied on volume " , volume.Name)
        if regexVolumeKubeApiAccess.MatchString(volume.Name) {
            volumesRemoved = append(volumesRemoved, volume.Name)
        }
    }
    for _, vrName := range volumesRemoved {
        pod.Spec.Volumes = deleteVolume(pod.Spec.Volumes, vrName)
    }

    // spec fields containers
    for ic, container := range pod.Spec.Containers {
        log.Debug("removing from container %v probes", container.Name)
        pod.Spec.Containers[ic].LivenessProbe = nil
        pod.Spec.Containers[ic].ReadinessProbe = nil
        pod.Spec.Containers[ic].StartupProbe = nil
        log.Debug("removing from container %v resource limits/requests", container.Name)
        pod.Spec.Containers[ic].Resources = corev1.ResourceRequirements{}
        log.Trace("removing from container %v volume mounts", container.Name)
        for _, vrmName := range volumesRemoved {
            pod.Spec.Containers[ic].VolumeMounts = deleteVolumeMount(pod.Spec.Containers[ic].VolumeMounts, vrmName)
        }
    }

    return pod
}

func (o *DebugWardOptions) treatPod(pod *corev1.Pod) (*corev1.Pod) {
    log.Trace("Starting treatPod")

    pod.ObjectMeta.Namespace = o.debugPodNamespace
    pod.ObjectMeta.Labels = map[string]string{
        "debug-ward": "true",
    }

    // set escalated priviledges
    if pod.Spec.SecurityContext == nil {
        log.Trace("treatPod on pod with empty SecurityContext")
        pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
    }

    pod.Spec.SecurityContext.RunAsUser = o.debugPodSecurityContextRunAsUser
    pod.Spec.SecurityContext.RunAsGroup = o.debugPodSecurityContextRunAsGroup
    pod.Spec.SecurityContext.FSGroup = o.debugPodSecurityContextFSGroup
    // pod.Spec.SecurityContext.FSGroupChangePolicy = o.debugPodSecurityContextFSGroupChangePolicy
    // pod.Spec.SecurityContext.SELinuxOptions = o.debugPodSecurityContextSELinuxOptions
    // pod.Spec.SecurityContext.SeccompProfile = o.debugPodSecurityContextSeccompProfile
    pod.Spec.SecurityContext.SupplementalGroups = o.debugPodSecurityContextSupplementalGroups
    pod.Spec.SecurityContext.Sysctls = o.debugPodSecurityContextSysctls

    // set escalated priviledges for each container
    for i, container := range pod.Spec.Containers {
       log.Trace("treatPod on container ", container.Name)
       if container.SecurityContext == nil {
           log.Trace("treatPod on container with empty security context")
           pod.Spec.Containers[i].SecurityContext = &corev1.SecurityContext{}
       }
       // container.SecurityContext.AllowPrivilegeEscalation = o.debugPodContainerSecurityContextAllowPrivilegeEscalation
       // container.SecurityContext.Capabilities = o.debugPodContainerSecurityContextCapabilities
       // container.SecurityContext.ProcMount = o.debugPodContainerSecurityContextProcMount

       pod.Spec.Containers[i].SecurityContext.Privileged = o.debugPodContainerSecurityContextPrivileged
       pod.Spec.Containers[i].SecurityContext.ReadOnlyRootFilesystem = o.debugPodContainerSecurityContextReadOnlyRootFilesystem
       pod.Spec.Containers[i].SecurityContext.RunAsUser = o.debugPodContainerSecurityContextRunAsUser
       pod.Spec.Containers[i].SecurityContext.RunAsGroup = o.debugPodContainerSecurityContextRunAsGroup
       pod.Spec.Containers[i].SecurityContext.RunAsNonRoot = o.debugPodContainerSecurityContextRunAsNonRoot

       // container.SecurityContext.SELinuxOptions = o.debugPodContainerSecurityContextSELinuxOptions
       // container.SecurityContext.SeccompProfile = o.debugPodContainerSecurityContextSeccompProfile
    }


    return pod
}

func deleteVolume(volumes []corev1.Volume, elementToDelete string) []corev1.Volume {
    log.Debug("deleting volume ", elementToDelete)

    var updatedVolumes []corev1.Volume

    for _, volume := range volumes {
        if volume.Name != elementToDelete {
            updatedVolumes = append(updatedVolumes, volume)
        }
    }

    return updatedVolumes
}

func deleteVolumeMount(volumes []corev1.VolumeMount, elementToDelete string) []corev1.VolumeMount {
    log.Debug("deleting volume ", elementToDelete)

    var updatedVolumes []corev1.VolumeMount

    for _, volume := range volumes {
        if volume.Name != elementToDelete {
            updatedVolumes = append(updatedVolumes, volume)
        }
    }

    return updatedVolumes
}

func cleanConfigMaps(configMaps []*corev1.ConfigMap) ([]*corev1.ConfigMap) {
    log.Trace("Starting cleanConfigMaps")

    for icm, configMap := range configMaps {
        configMaps[icm] = cleanConfigMap(configMap)
    }

    return configMaps
}

func cleanConfigMap(configMap *corev1.ConfigMap) (*corev1.ConfigMap) {
    log.Trace("Starting cleanConfigMap")

    // main fields
    configMap.ObjectMeta.CreationTimestamp = metav1.Time{}
    configMap.ObjectMeta.ManagedFields = nil
    configMap.ObjectMeta.Namespace = ""
    configMap.ObjectMeta.UID = ""
    configMap.ObjectMeta.ResourceVersion = ""

    return configMap
}

func cleanSecrets(secrets []*corev1.Secret) ([]*corev1.Secret) {
    log.Trace("Starting cleanSecrets")

    for isec, secret := range secrets {
        secrets[isec] = cleanSecret(secret)
    }

    return secrets
}

func cleanSecret(secret *corev1.Secret) (*corev1.Secret) {
    log.Trace("Starting cleanSecret")

    // main fields
    secret.ObjectMeta.CreationTimestamp = metav1.Time{}
    secret.ObjectMeta.ManagedFields = nil
    secret.ObjectMeta.Namespace = ""
    secret.ObjectMeta.UID = ""
    secret.ObjectMeta.ResourceVersion = ""

    return secret
}

func (o *DebugWardOptions) treatConfigMaps(configMaps []*corev1.ConfigMap) ([]*corev1.ConfigMap) {
    log.Trace("Starting treatConfigMap")

    for icm, _ := range configMaps {
        configMaps[icm].ObjectMeta.Namespace = o.debugPodNamespace
        configMaps[icm].ObjectMeta.Labels = map[string]string{
            "debug-ward": "true",
        }
    }

    return configMaps
}

func (o *DebugWardOptions) treatSecrets(secrets []*corev1.Secret) ([]*corev1.Secret) {
    log.Trace("Starting treatSecret")

    for isec, _ := range secrets {
    secrets[isec].ObjectMeta.Namespace = o.debugPodNamespace
        secrets[isec].ObjectMeta.Labels = map[string]string{
            "debug-ward": "true",
        }
    }

    return secrets
}

func (o *DebugWardOptions) createResource(clientset *kubernetes.Clientset, yamlData []byte, resourceType string) error {
    log.Trace("Starting createResource ", resourceType, string(yamlData))

    // Create resource in the cluster
    resource := clientset.CoreV1().RESTClient().Post().
        Resource(resourceType).
        Namespace(o.debugPodNamespace).
        Name("test-sebastian").
        Body(yamlData).
        Do(context.TODO())

    log.Debug(resource)
    // if err != nil {
    //     log.Panic("Error creating resource type %v: %v\n", resourceType, err)
    // }


    return nil
}

func getResourceName(yamlData []byte) string {
    lines := strings.Split(string(yamlData), "\n")
    for i, line := range lines {
        if strings.HasPrefix(line, "metadata:") && i+1 < len(lines) {
            // Check for the next line that contains the resource name
            rname := strings.TrimSpace(strings.Split(lines[i+1], ":")[1])
            log.Trace("getResourceName is ", rname)
            return rname
        }
    }
    return ""
}

func isContextEqual(ctxA, ctxB *api.Context) bool {
    if ctxA == nil || ctxB == nil {
        return false
    }
    if ctxA.Cluster != ctxB.Cluster {
        return false
    }
    if ctxA.Namespace != ctxB.Namespace {
        return false
    }
    if ctxA.AuthInfo != ctxB.AuthInfo {
        return false
    }

    return true
}

