FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
RUN chmod +x /repo/scripts/InstallPrerequisites-Ubuntu.sh
RUN /repo/scripts/InstallPrerequisites-Ubuntu.sh
WORKDIR /repo/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_hsvToHsl.cpp -fsanitize=fuzzer,address -I /repo/src/ -std=c++20 -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/build/staticExecutable/shasta /
COPY --from=builder /fuzz /fuzz_hsvToHsl
