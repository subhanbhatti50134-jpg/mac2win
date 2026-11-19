using Xunit;

// Perf measurements sample the *process* working set (PerfEnv.SampleLoop), so any other
// test class running at the same time in this testhost contaminates the baseline/peak —
// xUnit v2 parallelizes collections (one per class) by default. CI caught this: on a
// 4-core runner the 100 MiB case peaked at 19.3 MB vs 3.4 MB locally, tripping the
// "flat regardless of size" window while the machine was also running the other perf
// classes. Measuring memory requires a quiet process, so run perf tests one at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
