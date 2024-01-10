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
    "gopkg.in/yaml.v3"
    "strings"
    "regexp"
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
    %[1]s debug-ward -n pod-namespace pod --dry-run true

    # examples of pod secuirty context values that can be ovewritten
    %[1]s debug-ward -n pod-namespace pod --dry-run true --psc-runasuser 0 --psc-runasgroup 0 --psc-fsgroup 0 --psc-fsgroupchangepolicy Always --psc-selinuxoptions "IMPLEMENTE_ME" --psc-seccompprofile "IMPLEMENT_ME" --psc-supplementalgroups "IMPLEMENT_1,IMPLEMENT_2" --psc-sysctls "IMPLEMENT_ME_1,IMPLEMENTE_ME_2"

    # examples of pod constainer secuirty context values that can be ovewritten
    %[1]s debug-ward -n pod-namespace pod --dry-run true --pcsc-allowprivilegeescalation true --pcsc-capabilities "IMPLEMENT_ME" --pcsc-privileged true --pcsc-procmount "IMPLEMENT_ME" --pcsc-readonlyfilesystem false --pcsc-runasuser 0 --pcsc-runasgroup 0 --pcsc-runasnonroot false --pcsc-selinuxoptions "IMPLEMENTE_ME" --pcsc-seccompprofile "IMPLEMENT_ME"
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
    // debugPodContainerSecurityContextPrivileged               *bool
    debugPodContainerSecurityContextProcMount                *corev1.ProcMountType
    // debugPodContainerSecurityContextReadOnlyRootFilesystem   *bool
    debugPodContainerSecurityContextRunAsUser                *int64
    debugPodContainerSecurityContextRunAsGroup               *int64
    // debugPodContainerSecurityContextRunAsNonRoot             *bool
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

        debugPodSecurityContextRunAsUser: new(int64),
        debugPodSecurityContextRunAsGroup: new(int64),
        debugPodSecurityContextFSGroup: new(int64),
	// debugPodSecurityContextFSGroupChangePolicy: corev1.PodFSGroupChangeAlways,
        debugPodSecurityContextSELinuxOptions: &corev1.SELinuxOptions{},
        debugPodSecurityContextSeccompProfile: &corev1.SeccompProfile{},
        debugPodSecurityContextSupplementalGroups: []int64{},
        debugPodSecurityContextSysctls: []corev1.Sysctl{},

        // debugPodContainerSecurityContextAllowPrivilegeEscalation: &corev1.AllowPrivilegeEscalation{},
        // debugPodContainerSecurityContextCapabilities: corev1.Capabilities,
        // debugPodContainerSecurityContextPrivileged: true,
        // debugPodContainerSecurityContextProcMount: &corev1.ProcMountType,
        // debugPodContainerSecurityContextReadOnlyRootFilesystem: false,
        debugPodContainerSecurityContextRunAsUser: new(int64),
        debugPodContainerSecurityContextRunAsGroup: new(int64),
        // debugPodContainerSecurityContextRunAsNonRoot: false,
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
    secrets, err := getSecretsFromPod(o.srcK8sClient, pod)
    if err != nil {
        return err
    }

    log.Trace("Starting Run: get ConfigMaps")
    configMaps, err := getConfigMapsFromPod(o.srcK8sClient, pod)
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
    configMapsTreat := treatConfigMaps(configMapsClean)
    secretsTreat := treatSecrets(secretsClean)

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
        err := printr.PrintObj(configMap, os.Stdout)
        if err != nil {
            log.Panic(err)
        }
    }

    for _, secret := range secrets {
        err := printr.PrintObj(secret, os.Stdout)
        if err != nil {
            log.Panic(err)
        }
    }

    err := printr.PrintObj(pod, os.Stdout)
    if err != nil {
       log.Panic(err)
    }

    return nil
}

func (o *DebugWardOptions) debugWardCopy(pod *corev1.Pod, configMaps []*corev1.ConfigMap, secrets []*corev1.Secret) error {
    log.Trace("Starting debugWardCopy")
    log.Info("\n# ConfigMaps YAML")
    for _, configMap := range configMaps {
        log.Info("\n---")
        configMapYAML, err := yaml.Marshal(configMap)
        if err != nil {
            return err
        }
        err = createResource(o.srcK8sClient, configMapYAML, "ConfigMap")
        if err != nil {
            log.Fatal("Error creating ConfigMap: ", err)
        }
        log.Info("ConfigMap created successfully.")
    }

    log.Info("\n# Secrets YAML")
    for _, secret := range secrets {
        log.Info("\n---")
        secretYAML, err := yaml.Marshal(secret)
        if err != nil {
            return err
        }
        err = createResource(o.srcK8sClient, secretYAML, "Secret")
        if err != nil {
            log.Fatal("Error creating Secret: ", err)
        }
        log.Info("Secret created successfully.")
    }

    log.Info("\n# Pod YAML")
    log.Info("\n---")
    podYAML, err := yaml.Marshal(pod)
    if err != nil {
        return err
    }
    err = createResource(o.srcK8sClient, podYAML, "Pod")
    if err != nil {
        log.Fatal("Error creating Pod: ", err)
    }
    log.Info("Pod created successfully.")

    return nil
}

func getSecretsFromPod(clientset *kubernetes.Clientset, pod *corev1.Pod) ([]*corev1.Secret, error) {
    log.Trace("Starting getSecretsFromPod")
    var secrets []*corev1.Secret

    // Check volumes for secrets
    for _, volume := range pod.Spec.Volumes {
        if volume.Secret != nil {
            secret, err := clientset.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), volume.Secret.SecretName, metav1.GetOptions{})
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
                secret, err := clientset.CoreV1().Secrets(pod.Namespace).Get(context.TODO(), env.ValueFrom.SecretKeyRef.Name, metav1.GetOptions{})
                if err != nil {
                    return nil, err
                }
                secrets = append(secrets, secret)
            }
        }
    }

    return secrets, nil
}

func getConfigMapsFromPod(clientset *kubernetes.Clientset, pod *corev1.Pod) ([]*corev1.ConfigMap, error) {
    log.Trace("Starting getConfigMapsFromPod")
    var configMaps []*corev1.ConfigMap

    // Check volumes for config maps
    for _, volume := range pod.Spec.Volumes {
        if volume.ConfigMap != nil {
            configMap, err := clientset.CoreV1().ConfigMaps(pod.Namespace).Get(context.TODO(), volume.ConfigMap.Name, metav1.GetOptions{})
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
                configMap, err := clientset.CoreV1().ConfigMaps(pod.Namespace).Get(context.TODO(), env.ValueFrom.ConfigMapKeyRef.Name, metav1.GetOptions{})
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
        log.Debug("removing from container %s probes", container.Name)
        pod.Spec.Containers[ic].LivenessProbe = nil
        pod.Spec.Containers[ic].ReadinessProbe = nil
        pod.Spec.Containers[ic].StartupProbe = nil
        log.Debug("removing from container %s resource limits/requests", container.Name)
        pod.Spec.Containers[ic].Resources = corev1.ResourceRequirements{}
        log.Trace("removing from container %s volume mounts", container.Name)
        for _, vrmName := range volumesRemoved {
            pod.Spec.Containers[ic].VolumeMounts = deleteVolumeMount(pod.Spec.Containers[ic].VolumeMounts, vrmName)
        }
    }

    return pod
}

func (o *DebugWardOptions) treatPod(pod *corev1.Pod) (*corev1.Pod) {
    log.Trace("Starting treatPod")

    pod.ObjectMeta.Labels = map[string]string{
        "debug-ward": "true",
    }

    // set escalated priviledges
    pod.Spec.SecurityContext.RunAsUser = o.debugPodSecurityContextRunAsUser
    pod.Spec.SecurityContext.RunAsGroup = o.debugPodSecurityContextRunAsGroup
    pod.Spec.SecurityContext.FSGroup = o.debugPodSecurityContextFSGroup
    // pod.Spec.SecurityContext.FSGroupChangePolicy = o.debugPodSecurityContextFSGroupChangePolicy
    // pod.Spec.SecurityContext.SELinuxOptions = o.debugPodSecurityContextSELinuxOptions
    // pod.Spec.SecurityContext.SeccompProfile = o.debugPodSecurityContextSeccompProfile
    pod.Spec.SecurityContext.SupplementalGroups = o.debugPodSecurityContextSupplementalGroups
    pod.Spec.SecurityContext.Sysctls = o.debugPodSecurityContextSysctls

    // set escalated priviledges for each container
    for _, container := range pod.Spec.Containers {
       // container.SecurityContext.AllowPrivilegeEscalation = o.debugPodContainerSecurityContextAllowPrivilegeEscalation
       // container.SecurityContext.Capabilities = o.debugPodContainerSecurityContextCapabilities
       // container.SecurityContext.Privileged = o.debugPodContainerSecurityContextPrivileged
       // container.SecurityContext.ProcMount = o.debugPodContainerSecurityContextProcMount
       // container.SecurityContext.ReadOnlyRootFilesystem = o.debugPodContainerSecurityContextReadOnlyRootFilesystem
       container.SecurityContext.RunAsUser = o.debugPodContainerSecurityContextRunAsUser
       container.SecurityContext.RunAsGroup = o.debugPodContainerSecurityContextRunAsGroup
       // container.SecurityContext.RunAsNonRoot = o.debugPodContainerSecurityContextRunAsNonRoot
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

func treatConfigMaps(configMaps []*corev1.ConfigMap) ([]*corev1.ConfigMap) {
    log.Trace("Starting treatConfigMap")

    for icm, _ := range configMaps {
        configMaps[icm].ObjectMeta.Labels = map[string]string{
            "debug-ward": "true",
        }
    }

    return configMaps
}

func treatSecrets(secrets []*corev1.Secret) ([]*corev1.Secret) {
    log.Trace("Starting treatSecret")

    for isec, _ := range secrets {
        secrets[isec].ObjectMeta.Labels = map[string]string{
            "debug-ward": "true",
        }
    }

    return secrets
}

func createResource(clientset *kubernetes.Clientset, yamlData []byte, resourceType string) error {
    log.Trace("Starting createResource")
    // Create resource in the cluster
    _, err := clientset.CoreV1().RESTClient().Post().
        Resource(getResourceType(yamlData)).
        Namespace(getResourceNamespace(yamlData)).
        Name(getResourceName(yamlData)).
        Body(yamlData).
        Do(context.Background()).
        Get()

    if err != nil {
        return fmt.Errorf("failed to create ", resourceType, err)
    }
    return nil
}

func getResourceType(yamlData []byte) string {
    lines := strings.Split(string(yamlData), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "kind:") {
            parts := strings.Split(line, ":")
            return strings.TrimSpace(parts[1])
        }
    }
    return ""
}

func getResourceNamespace(yamlData []byte) string {
    lines := strings.Split(string(yamlData), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "namespace:") {
            parts := strings.Split(line, ":")
            return strings.TrimSpace(parts[1])
        }
    }
    return "default" // Default namespace if not specified
}

func getResourceName(yamlData []byte) string {
    lines := strings.Split(string(yamlData), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "metadata:") {
            // Check for the next line that contains the resource name
            if len(lines) > 1 {
                return strings.TrimSpace(strings.Split(lines[1], ":")[1])
            }
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

