#!/system/bin/sh
set -eu

trace=/sys/kernel/tracing
instance="$trace/instances/rmg_fpsimd"
copy_event=rmg_fpsimd_copy
copy_dir="$instance/events/kprobes/$copy_event"
global_copy_dir="$trace/events/kprobes/$copy_event"
waiter_event=rmg_waiter_init
waiter_dir="$instance/events/kprobes/$waiter_event"
global_waiter_dir="$trace/events/kprobes/$waiter_event"

cleanup() {
    if [ -e "$instance/tracing_on" ]; then
        echo 0 > "$instance/tracing_on"
    fi
    if [ -e "$copy_dir/enable" ]; then
        echo 0 > "$copy_dir/enable"
    fi
    if [ -e "$waiter_dir/enable" ]; then
        echo 0 > "$waiter_dir/enable"
    fi
    if [ -e "$global_copy_dir/enable" ]; then
        echo 0 > "$global_copy_dir/enable"
        echo "-:kprobes/$copy_event" >> "$trace/kprobe_events"
    fi
    if [ -e "$global_waiter_dir/enable" ]; then
        echo 0 > "$global_waiter_dir/enable"
        echo "-:kprobes/$waiter_event" >> "$trace/kprobe_events"
    fi
    if [ -d "$instance" ]; then
        rmdir "$instance"
    fi
}

case "${1:-}" in
    setup)
        cleanup
        mkdir "$instance"
        echo 'r128:kprobes/rmg_fpsimd_copy __arch_copy_from_user ret=$retval sp=$stack task=$comm q0=+0x100($stack):x64 q1=+0x108($stack):x64 q2=+0x110($stack):x64 q3=+0x118($stack):x64 q4=+0x120($stack):x64 q5=+0x128($stack):x64 q6=+0x130($stack):x64 q7=+0x138($stack):x64 q8=+0x140($stack):x64 q9=+0x148($stack):x64' >> "$trace/kprobe_events"
        echo 'p:kprobes/rmg_waiter_init rt_mutex_init_waiter waiter=$arg1:x64 task=$comm' >> "$trace/kprobe_events"
        echo > "$instance/trace"
        echo 'task == "fpsimd-poc"' > "$copy_dir/filter"
        echo 'task == "fpsimd-poc"' > "$waiter_dir/filter"
        echo 1 > "$copy_dir/enable"
        echo 1 > "$waiter_dir/enable"
        echo 1 > "$instance/tracing_on"
        cat "$copy_dir/filter"
        cat "$waiter_dir/filter"
        ;;
    capture)
        echo 0 > "$instance/tracing_on"
        cat "$instance/trace"
        cat "$trace/kprobe_profile"
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "use: fpsimd-kprobe.sh setup|capture|cleanup" >&2
        exit 2
        ;;
esac
