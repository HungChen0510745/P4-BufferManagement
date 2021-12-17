# P4-BufferManagement

## Description

Dynamic Threshold is the orirginal built-in buffer managment in Tofino Switch. We implement the buffer managemnt by computing the threshold based on the current buffer state in the Egress and storing the threshold and queue length in the Ingress.
The method of buffer managemnt is based on a reference to TDT (Traffic-Aware Buffer Management on Shared Memory Switch). We convert it to a queue-based mode and deploy Quality of Service to priovide additional space for high priority flow.

## Contribution

1. Management according to the priority of flow
2. Queue-based Control
