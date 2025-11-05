# cc-cvm-docs

Confidential computing is a concept that protects sensitive data while it's being actively processed by the CPU.

Traditional security models rather focussed on encrypting and securing data in transit and at rest. From and end-to-end perspective these models left a critical security-gap that might be misused by attackers. 

Yet applying confidentiality to your application-data while it's processed is not (yet?) an out-of-the-box-approach. It comes at the price of increased complexity which has to be managed by application-owners and operational-teams. 

As a rule of thumb - the higher the level of confidentiality, the more complexity we add. And different confidential-computing-flavors offer different levels of confidentiality (the so called 'Trusted Computing Base', TCB). 

In general, it can be said that securing a single process offers most protection while also adding the most complexity. In contrast, securing a whole VM is less complex while exposing more attack-surface. These two flavors (process- vs. VM-protection) are enabled by hardware vendors with specific CPU-types (e.g. Intex SGX/TDX or AMD SEV-SNP).

This document evolves concepts and design patterns for possible confidential VM (CVM) use cases based on Intel TDX. 
 [cvm.md](cvm.md) provides a comprehensive description of the requirements related to CVMs based on Kubernetes workloads.

