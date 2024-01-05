/*
Copyright 2018 The Kubernetes Authors.

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
    "os"
    "gopkg.in/yaml.v3"
    "strings"

    "github.com/spf13/cobra"

    corev1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

    log "github.com/sirupsen/logrus"

    "k8s.io/client-go/kubernetes"

    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/clientcmd/api"


    "k8s.io/cli-runtime/pkg/genericclioptions"
    "k8s.io/cli-runtime/pkg/genericiooptions"
)

var (
    runExample = `
    # with dry-run set to true will create a YAML file of what will be created if set to false
    %[1]s copy -n pod-namespace -p pod --dry-run true

    # examples of pod secuirty context values that can be ovewritten
    %[1]s copy -n pod-namespace -p pod --dry-run true --psc-runasuser 0 --psc-runasgroup 0 --psc-fsgroup 0 --psc-fsgroupchangepolicy Always --psc-selinuxoptions "IMPLEMENTE_ME" --psc-seccompprofile "IMPLEMENT_ME" --psc-supplementalgroups "IMPLEMENT_1,IMPLEMENT_2" --psc-sysctls "IMPLEMENT_ME_1,IMPLEMENTE_ME_2"

    # examples of pod constainer secuirty context values that can be ovewritten
    %[1]s copy -n pod-namespace -p pod --dry-run true --pcsc-allowprivilegeescalation true --pcsc-capabilities "IMPLEMENT_ME" --pcsc-privileged true --pcsc-procmount "IMPLEMENT_ME" --pcsc-readonlyfilesystem false --pcsc-runasuser 0 --pcsc-runasgroup 0 --pcsc-runasnonroot false --pcsc-selinuxoptions "IMPLEMENTE_ME" --pcsc-seccompprofile "IMPLEMENT_ME"
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
    debugPodSecurityContextRunAsUser           int
    debugPodSecurityContextRunAsGroup          int
    debugPodSecurityContextFsGroup             int
    debugPodSecurityContextFsGroupChangePolicy string
    debugPodSecurityContextSeLinuxOptions      string
    debugPodSecurityContextSeccompProfile      string
    debugPodSecurityContextSupplementalGroups  []int
    debugPodSecurityContextSysctls             []string

    debugPodContainerSecurityContextAllowPrivilegeEscalation bool
    debugPodContainerSecurityContextCapabilities             string
    debugPodContainerSecurityContextPriviledged              bool
    debugPodContainerSecurityContextProcMount                string
    debugPodContainerSecurityContextReadOnlyRootFilesystem   bool
    debugPodContainerSecurityContextRunAsUser                int
    debugPodContainerSecurityContextRunAsGroup               int
    debugPodContainerSecurityContextRunAsNonRoot             bool
    debugPodContainerSecurityContextSeLinuxOptions           string
    debugPodContainerSecurityContextSeccompProfile           string

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

        debugPodSecurityContextRunAsUser: 0,
        debugPodSecurityContextRunAsGroup: 0,
        debugPodSecurityContextFsGroup: 0,
        debugPodSecurityContextFsGroupChangePolicy: "Always",
        debugPodSecurityContextSeLinuxOptions: "",
        debugPodSecurityContextSeccompProfile: "",
        debugPodSecurityContextSupplementalGroups: []int{},
        debugPodSecurityContextSysctls: []string{},

        debugPodContainerSecurityContextAllowPrivilegeEscalation: true,
        debugPodContainerSecurityContextCapabilities: "",
        debugPodContainerSecurityContextPriviledged: true,
        debugPodContainerSecurityContextProcMount: "",
        debugPodContainerSecurityContextReadOnlyRootFilesystem: false,
        debugPodContainerSecurityContextRunAsUser: 0,
        debugPodContainerSecurityContextRunAsGroup: 0,
        debugPodContainerSecurityContextRunAsNonRoot: false,
        debugPodContainerSecurityContextSeLinuxOptions: "",
        debugPodContainerSecurityContextSeccompProfile: "",

        IOStreams: streams,
    }
}

// NewDebugWardPatient provides a cobra command wrapping DebugWardOptions
func NewDebugWardPatient(streams genericiooptions.IOStreams) *cobra.Command {
    log.Trace("Starting NewDebugWardOptions")
    o := NewDebugWardOptions(streams)

    cmd := &cobra.Command{
        Use:          "debug-ward [new-namespace] [flags]",
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

    cmd.Flags().StringVar(&o.sourcePodCluster, "cluster", o.sourcePodCluster, "defaults to ")
    cmd.Flags().StringVar(&o.sourcePodUser, "user", o.sourcePodUser, "defaults to ")
    cmd.Flags().StringVar(&o.sourcePodContext, "context", o.sourcePodContext, "defaults to ")
    cmd.Flags().StringVar(&o.sourcePodNamespace, "namespace", o.sourcePodNamespace, "defaults to default")
    cmd.Flags().BoolVar(&o.dryRun, "dry-run", o.dryRun, "if true, print the yaml of the pod that is going to be created in the debug-ward namespace; default true")
    // o.configFlags.AddFlags(cmd.Flags())

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
    // config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
    // if err != nil {
    //     log.Fatal(err)
    // }

    o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
    if err != nil {
        return err
    }

    // o.srcK8sClient, err = kubernetes.NewForConfig(config)
    // if err != nil {
    //     log.Fatal("Error creating Kubernetes source client: \n", err)
    // }

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

    log.Trace("setting context s10...")
    currentContext, exists := o.rawConfig.Contexts[o.rawConfig.CurrentContext]
    if !exists {
	log.Trace("setting context s10001...")
        return errNoContext
    }

    log.Trace("setting context s11...")
    o.resultingContext = api.NewContext()
    o.resultingContext.Cluster = currentContext.Cluster
    o.resultingContext.AuthInfo = currentContext.AuthInfo

    log.Trace("setting context s12...")
    // if a target context is explicitly provided by the user,
    // use that as our reference for the final, resulting context
    if len(o.sourcePodContext) > 0 {
        o.resultingContextName = o.sourcePodContext
        if userCtx, exists := o.rawConfig.Contexts[o.sourcePodContext]; exists {
            o.resultingContext = userCtx.DeepCopy()
        }
    }

    log.Trace("setting context s13...")

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
    if len(o.args) > 1 {
        return fmt.Errorf("either one or no arguments are allowed")
    }

    return nil
}

// Run copy of debug pod using the provided options
func (o *DebugWardOptions) Run() error {
    log.Trace("Starting Run")
    // if len(o.sourcePodNamespace) > 0 && o.resultingContext != nil {
    //     return o.setNamespace(o.resultingContext, o.resultingContextName)
    // }

    pod, err := o.srcK8sClient.CoreV1().Pods(o.sourcePodNamespace).Get(context.TODO(), o.sourcePodName, metav1.GetOptions{})
    if err != nil {
        return err
    }

    // Get associated secrets and config maps
    secrets, err := getSecretsFromPod(o.srcK8sClient, pod)
    if err != nil {
        return err
    }

    configMaps, err := getConfigMapsFromPod(o.srcK8sClient, pod)
    if err != nil {
        return err
    }

    // ###################
    // remove secrets/ configMap duplicates to avoid errors during creation
    // ###################
    if o.dryRun == true {
        o.debugWardDryRun(pod, configMaps, secrets)
    } else {
        o.debugWardCopy(pod, configMaps, secrets)
    }


    return nil
}

func (o *DebugWardOptions) debugWardDryRun(pod *corev1.Pod, configMaps []*corev1.ConfigMap, secrets []*corev1.Secret) error {
    log.Trace("Starting debugWardDryRun")
    log.Info("\n# ConfigMaps YAML")
    for _, configMap := range configMaps {
        log.Info("\n---")
        configMapYAML, err := yaml.Marshal(configMap)
        if err != nil {
            return err
        }
        log.Info(string(configMapYAML))
    }

    log.Info("\n# Secrets YAML")
    for _, secret := range secrets {
        log.Info("\n---")
        secretYAML, err := yaml.Marshal(secret)
        if err != nil {
            return err
        }
        log.Info(string(secretYAML))
    }

    log.Info("\n# Pod YAML")
    log.Info("\n---")
    podYAML, err := yaml.Marshal(pod)
    if err != nil {
        return err
    }
    log.Info(string(podYAML))

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

func (o *DebugWardOptions) setNamespace(fromContext *api.Context, withContextName string) error {
    log.Trace("Starting setNamespace")
    if len(fromContext.Namespace) == 0 {
        return fmt.Errorf("a non-empty namespace must be provided")
    }

    configAccess := clientcmd.NewDefaultPathOptions()

    // determine if we have already saved this context to the user's KUBECONFIG before
    // if so, simply switch the current context to the existing one.
    if existingResultingCtx, exists := o.rawConfig.Contexts[withContextName]; !exists || !isContextEqual(fromContext, existingResultingCtx) {
        o.rawConfig.Contexts[withContextName] = fromContext
    }
    o.rawConfig.CurrentContext = withContextName

    fmt.Fprintf(o.Out, "namespace changed to %q\n", fromContext.Namespace)
    return clientcmd.ModifyConfig(configAccess, o.rawConfig, true)
}
