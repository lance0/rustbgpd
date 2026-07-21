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

FROM gcr.io/oss-fuzz-base/base-builder-rust:ubuntu-24-04
COPY . $SRC/rustbgpd
WORKDIR $SRC/rustbgpd
RUN toolchain="$(cat fuzz/rust-nightly.txt)" \
    && rustup toolchain install "$toolchain" --profile minimal --target x86_64-unknown-linux-gnu \
    && cargo "+$toolchain" install cargo-fuzz --version 0.13.2 --locked
COPY .clusterfuzzlite/build.sh $SRC/
