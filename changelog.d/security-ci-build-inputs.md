### Security

- Pin external workflow actions to full commit SHAs and container base images
  to digests, with checks that reject mutable references. Dependabot tracks
  action pins and Dockerfile base-image digests.
