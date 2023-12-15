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
*/

package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
)

var (
	runExample = `
	# view the current namespace in your KUBECONFIG
	%[1]s run -n pod-namespace -p pod

	# view all of the namespaces in use by contexts in your KUBECONFIG
	%[1]s get -n XYZ pod,configmap,secret

	# switch your current-context to one that contains the desired namespace
	%[1]s ns foo
`

	errNoContext = fmt.Errorf("no context is currently set, use %q to select a new one", "kubectl config use-context <context>")
)

if os.Getenv("K8S_DEBUG_POD_NAME_PREFIX") != "" {
        k8sDebugPodNamePrefix = os.Geten("K8S_DEBUG_POD_NAME_PREFIX")
}


// DebugWardOptions provides information required to update
// the current context on a user's KUBECONFIG
type DebugWardOptions struct {
	configFlags *genericclioptions.ConfigFlags

	resultingContext     *api.Context
	resultingContextName string

	sourcePodNamespace: string
	sourcePodName:      string

	debugPodNamespace  string
	debugPodNamePrefix string
	debugPodImage      string
	debugPodCommand    string

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

	dryRun bool

	rawConfig      api.Config
	listNamespaces bool
	args           []string

	genericiooptions.IOStreams
}

// NewDebugWardOptions provides an instance of DebugWardOptions with default values
func NewDebugWardOptions(streams genericiooptions.IOStreams) *DebugWardOptions {
	return &DebugWardOptions{
		configFlags: genericclioptions.NewConfigFlags(true),

		sourcePodNamespace: "default"
		sourcePodName: ""

		debugPodNamespace: "debug-ward-tmp"
		debugPodNamePrefix: "dwpt"
		debugPodImage: "ubuntu:22.04"
		debugPodCommand: "bash"

		debugPodSecurityContextRunAsUser: 0
		debugPodSecurityContextRunAsGroup: 0
		debugPodSecurityContextFsGroup: 0
		debugPodSecurityContextFsGroupChangePolicy: "Always"
		debugPodSecurityContextSeLinuxOptions: ""
		debugPodSecurityContextSeccompProfile: ""
		debugPodSecurityContextSupplementalGroups: []
		debugPodSecurityContextSysctls: []

		debugPodContainerSecurityContextAllowPrivilegeEscalation: true
		debugPodContainerSecurityContextCapabilities: ""
		debugPodContainerSecurityContextPriviledged: true
		debugPodContainerSecurityContextProcMount: ""
		debugPodContainerSecurityContextReadOnlyRootFilesystem: false
		debugPodContainerSecurityContextRunAsUser: 0
		debugPodContainerSecurityContextRunAsGroup: 0
		debugPodContainerSecurityContextRunAsNonRoot: false
		debugPodContainerSecurityContextSeLinuxOptions: ""
		debugPodContainerSecurityContextSeccompProfile: ""

		IOStreams: streams,
	}
}

// NewCmdDebugWard provides a cobra command wrapping DebugWardOptions
func NewCmdDebugWard(streams genericiooptions.IOStreams) *cobra.Command {
	o := NewDebugWardOptions(streams)

	cmd := &cobra.Command{
		Use:          "ns [new-namespace] [flags]",
		Short:        "View or set the current namespace",
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

	cmd.Flags().BoolVar(&o.listNamespaces, "list", o.listNamespaces, "if true, print the list of all namespaces in the current KUBECONFIG")
	o.configFlags.AddFlags(cmd.Flags())

	return cmd
}

// Complete sets all information required for updating the current context
func (o *DebugWardOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args

	var err error
	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	o.userSpecifiedNamespace, err = cmd.Flags().GetString("namespace")
	if err != nil {
		return err
	}
	if len(args) > 0 {
		if len(o.userSpecifiedNamespace) > 0 {
			return fmt.Errorf("cannot specify both a --namespace value and a new namespace argument")
		}

		o.userSpecifiedNamespace = args[0]
	}

	// if no namespace argument or flag value was specified, then there
	// is no need to generate a resulting context
	if len(o.userSpecifiedNamespace) == 0 {
		return nil
	}

	o.userSpecifiedCluster, err = cmd.Flags().GetString("cluster")
	if err != nil {
		return err
	}

	o.userSpecifiedAuthInfo, err = cmd.Flags().GetString("user")
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

	// override context info with user provided values
	o.resultingContext.Namespace = o.userSpecifiedNamespace

	if len(o.userSpecifiedCluster) > 0 {
		o.resultingContext.Cluster = o.userSpecifiedCluster
	}
	if len(o.userSpecifiedAuthInfo) > 0 {
		o.resultingContext.AuthInfo = o.userSpecifiedAuthInfo
	}

	return nil
}

// Validate ensures that all required arguments and flag values are provided
func (o *DebugWardOptions) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errNoContext
	}
	if len(o.args) > 1 {
		return fmt.Errorf("either one or no arguments are allowed")
	}

	return nil
}

// Run lists all available namespaces on a user's KUBECONFIG or updates the
// current context based on a provided namespace.
func (o *DebugWardOptions) Run() error {
	if len(o.userSpecifiedNamespace) > 0 && o.resultingContext != nil {
		return o.setNamespace(o.resultingContext, o.resultingContextName)
	}

	namespaces := map[string]bool{}

	for name, c := range o.rawConfig.Contexts {
		if !o.listNamespaces && name == o.rawConfig.CurrentContext {
			if len(c.Namespace) == 0 {
				return fmt.Errorf("no namespace is set for your current context: %q", name)
			}

			fmt.Fprintf(o.Out, "%s\n", c.Namespace)
			return nil
		}

		// skip if dealing with a namespace we have already seen
		// or if the namespace for the current context is empty
		if len(c.Namespace) == 0 {
			continue
		}
		if namespaces[c.Namespace] {
			continue
		}

		namespaces[c.Namespace] = true
	}

	if !o.listNamespaces {
		return fmt.Errorf("unable to find information for the current namespace in your configuration")
	}

	for n := range namespaces {
		fmt.Fprintf(o.Out, "%s\n", n)
	}

	return nil
}

// setNamespace receives a "desired" context state and determines if a similar context
// is already present in a user's KUBECONFIG. If one is not, then a new context is added
// to the user's config under the provided destination name.
// The current context field is updated to point to the new context.
func (o *DebugWardOptions) setNamespace(fromContext *api.Context, withContextName string) error {
}
