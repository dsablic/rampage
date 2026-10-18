use std::hint::black_box;

fn main() {
    let mut values = vec![black_box(17_u64), black_box(3), black_box(29)];
    values.sort_unstable();
    let text = format!("runtime-reference:{}", values.iter().sum::<u64>());
    black_box(text);
}
