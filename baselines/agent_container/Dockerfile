# Image for the coding-agent baseline (--harness opencode_agent
# --agent-isolation docker). The agent runs inside it with only its own run
# directory mounted, so its shell cannot see the host's files: no checkout,
# no datasets, no other runs. Tool versions are pinned to what the host-side
# validators use, so "it passed cfn-lint in the container" means the same
# thing as when the scorer runs it.
#
#   docker build -t iacgod-agent:latest baselines/agent_container
FROM node:22-bookworm-slim

ARG TARGETARCH
ARG OPENCODE_VERSION=1.18.30
ARG CFN_LINT_VERSION=1.48.1
ARG YAMLLINT_VERSION=1.38.0
ARG TERRAFORM_VERSION=1.16.0
ARG TFLINT_VERSION=0.64.0
ARG AWS_CLI_VERSION=2.36.34
ARG TRIVY_VERSION=0.71.2
# Same checks-bundle pin the scorer uses (tools/validators.py _TRIVY_CHECKS_BUNDLE).
ARG TRIVY_CHECKS_BUNDLE=mirror.gcr.io/aquasec/trivy-checks:2@sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip git jq less groff python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 (official bundle, per architecture).
RUN case "${TARGETARCH:-amd64}" in arm64) a=aarch64 ;; *) a=x86_64 ;; esac \
 && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${a}-${AWS_CLI_VERSION}.zip" -o /tmp/aws.zip \
 && unzip -q /tmp/aws.zip -d /tmp && /tmp/aws/install && rm -rf /tmp/aws /tmp/aws.zip

# Terraform and TFLint.
RUN a="${TARGETARCH:-amd64}" \
 && curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${a}.zip" -o /tmp/tf.zip \
 && unzip -q /tmp/tf.zip -d /usr/local/bin terraform && rm /tmp/tf.zip \
 && curl -fsSL "https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}/tflint_linux_${a}.zip" -o /tmp/tfl.zip \
 && unzip -q /tmp/tfl.zip -d /usr/local/bin tflint && rm /tmp/tfl.zip

# cfn-lint and yamllint in their own venv, on PATH.
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir "cfn-lint==${CFN_LINT_VERSION}" "yamllint==${YAMLLINT_VERSION}"
ENV PATH="/opt/venv/bin:${PATH}"

# Trivy, the scorer's security scanner, with the pinned checks bundle baked into a
# world-writable cache so `trivy config` works offline as any host user and gives
# the same findings as the scorer.
RUN case "${TARGETARCH:-amd64}" in arm64) t=Linux-ARM64 ;; *) t=Linux-64bit ;; esac \
 && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${t}.tar.gz" -o /tmp/trivy.tgz \
 && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy && rm /tmp/trivy.tgz \
 && mkdir -p /opt/trivy-cache && chmod 777 /opt/trivy-cache \
 && mkdir /tmp/warm && printf 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n' > /tmp/warm/template.yaml \
 && TRIVY_CACHE_DIR=/opt/trivy-cache trivy config --checks-bundle-repository "${TRIVY_CHECKS_BUNDLE}" --format json /tmp/warm > /dev/null \
 && chmod -R a+rwX /opt/trivy-cache && rm -rf /tmp/warm
ENV TRIVY_CACHE_DIR=/opt/trivy-cache \
    TRIVY_CHECKS_BUNDLE_REPOSITORY="${TRIVY_CHECKS_BUNDLE}" \
    TRIVY_SKIP_CHECK_UPDATE=true \
    TRIVY_DISABLE_TELEMETRY=true

# OpenCode, the same version the host driver was verified against.
RUN npm install -g "opencode-ai@${OPENCODE_VERSION}" && npm cache clean --force

# The agent's own fetch tools are denied by permission rules; removing curl
# also takes away the easiest unrestricted download path in the image.
RUN apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Runs as the invoking host user (docker run --user), so HOME is set at run time.
WORKDIR /workspace
