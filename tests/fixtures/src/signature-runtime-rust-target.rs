use std::hint::black_box;

fn main() {
    let mut values = vec![black_box(41_u64), black_box(7), black_box(13), black_box(5)];
    values.reverse();
    let text = format!("runtime-target-distinct:{}", values.iter().product::<u64>());
    black_box(text);
}
