# Dockerfile for Inspektor Gadget CO-RE container image gadgets.
# This is a reduced gadget container image that supports only the CO-RE
# implementation of the gadgets, i.e, it doesn't depend on BCC. This
# image is much smaller than the image built with gadget.bcc.Dockerfile
# and is designed to be used on systems that support BTF
# (CONFIG_DEBUG_INFO_BTF).

ARG BUILDER_IMAGE=golang:1.19-bullseye
ARG BASE_IMAGE=debian:bullseye-slim

# Prepare and build gadget artifacts in a container
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETARCH
ARG BUILDARCH

# We need a cross compiler and libraries for TARGETARCH due to CGO.
RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git libelf-dev:${TARGETARCH} \
		pkg-config:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
		if [ ${TARGETARCH} = 'arm64' ]; then \
			apt-get install -y gcc-aarch64-linux-gnu; \
		elif [ ${TARGETARCH} = 'amd64' ]; then \
			apt-get install -y gcc-x86-64-linux-gnu; \
		else \
			>&2 echo "${TARGETARCH} is not supported"; \
			exit 1; \
		fi \
	fi

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget/gadget-container && \
	if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
		if [ ${TARGETARCH} = 'arm64' ]; then \
			export CC=aarch64-linux-gnu-gcc; \
			export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig/; \
		elif [ ${TARGETARCH} = 'amd64' ]; then \
			export CC=x86_64-linux-gnu-gcc; \
			export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig; \
		else \
			>&2 echo "${TARGETARCH} is not supported"; \
			exit 1; \
		fi \
	fi; \
	make -j$(nproc) TARGET_ARCH=${TARGETARCH} gadget-container-deps

# Main gadget image
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget k8s DaemonSet (core flavor)"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image is used as a long-running DaemonSet in Kubernetes via the kubectl-gadget deploy command or via the Helm charts. This is the core flavor (default flavor includes both bcc-based tools and CO-RE-based tools; core flavor includes only CO-RE-based tools)."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

# install runtime dependencies  according to the package manager
# available on the base image
RUN set -ex; \
	if command -v tdnf; then \
		tdnf install -y libseccomp wget util-linux socat; \
	elif command -v yum; then \
		yum install -y libseccomp wget util-linux socat; \
	elif command -v apt-get; then \
		apt-get update && \
		apt-get install -y seccomp wget util-linux socat && \
		apt-get clean && \
		rm -rf /var/lib/apt/lists/*; \
	elif command -v apk; then \
		apk add gcompat libseccomp wget util-linux socat; \
	fi && \
	(rmdir /usr/src || true) && ln -sf /host/usr/src /usr/src && \
	rm -f /etc/localtime && ln -sf /host/etc/localtime /etc/localtime

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY --from=builder /gadget/gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends

# BTF files
COPY hack/btfs /btfs/

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm -f /var/run

ENV GADGET_IMAGE_FLAVOUR=core
