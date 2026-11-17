// Package project holds the identifiers that change when the project is
// renamed or moved to a GitHub organization. Keep every occurrence of the
// project name, API group, owner and target platform here.
//
// Exception: kubebuilder markers (e.g. +groupName in api/v1alpha1) cannot
// reference Go constants and must be updated by hand.
package project

const (
	// Name is the project name in identifiers (CLI command, resource names).
	Name = "brokelabs"
	// APIGroup is the Kubernetes API group of all BrokeLabs resources.
	APIGroup = "brokelabs.io"
	// LabelPrefix prefixes every label and annotation set by BrokeLabs.
	LabelPrefix = APIGroup + "/"
	// Owner is the GitHub account hosting the repositories.
	Owner = "Sigeth"
	// ImageRegistry is where official images are published.
	ImageRegistry = "ghcr.io/sigeth"
	// OS and Arch are the only supported target platform.
	OS   = "linux"
	Arch = "amd64"
)
