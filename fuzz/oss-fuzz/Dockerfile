# Copyright 2026 the rustbgpd authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04@sha256:5d25f9344b91c893d58cdae0d1a57072f22d434bc60c3eab13795e42141fb127
RUN git clone --depth 1 https://github.com/lance0/rustbgpd rustbgpd
WORKDIR rustbgpd
RUN toolchain="$(cat fuzz/rust-nightly.txt)" \
    && rustup toolchain install "$toolchain" --profile minimal --target x86_64-unknown-linux-gnu \
    && cargo "+$toolchain" install cargo-fuzz --version 0.13.2 --locked
COPY build.sh $SRC/
