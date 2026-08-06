use nexus_core::ProcessSnapshot;

pub fn sort_by_cpu(mut processes: Vec<ProcessSnapshot>) -> Vec<ProcessSnapshot> {
    processes.sort_by(|a, b| {
        b.cpu_percent
            .partial_cmp(&a.cpu_percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    processes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_descending() {
        let a = ProcessSnapshot {
            pid: 1,
            name: "a".into(),
            user: "u".into(),
            status: "R".into(),
            cpu_percent: 1.0,
            memory_bytes: 1,
        };
        let b = ProcessSnapshot {
            pid: 2,
            name: "b".into(),
            user: "u".into(),
            status: "R".into(),
            cpu_percent: 5.0,
            memory_bytes: 1,
        };
        let out = sort_by_cpu(vec![a, b]);
        assert_eq!(out[0].pid, 2);
    }
}
