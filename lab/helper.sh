#!/bin/bash
# 测试辅助脚本（替代原来的 gen_input.py / sum_inputs.py / check.py）。
# 用法：
#   helper.sh gen   <N> <nints>   生成每个 rank 的发送内容 input-<r>.data
#   helper.sh sum   <N>           单机参考：按元素求和 -> expected-allreduce.data
#   helper.sh check <mode> <N>    按各原语语义做“文件 vs 文件”比对，打印 PASS/FAIL
set -u
cmd="${1:-}"; shift 2>/dev/null || true

case "$cmd" in
  gen)        # 内容随 rank 与下标变化，强校验数据完整性与聚合正确性
    N=$1; nints=$2
    for ((r=0; r<N; r++)); do
      seq 0 $((nints-1)) | awk -v r="$r" '{printf "%d\n", ($1*131 + r*1000003) % 1000000}' > "input-$r.data"
    done
    echo "generated $N input files, $nints ints each"
    ;;

  sum)        # 把所有输入按元素相加（paste 拼成列，awk 行内求和）
    N=$1
    files=(); for ((r=0; r<N; r++)); do files+=("input-$r.data"); done
    paste "${files[@]}" | awk '{s=0; for(i=1;i<=NF;i++) s+=$i; printf "%d\n", s}' > expected-allreduce.data
    echo "summed $N inputs -> expected-allreduce.data"
    ;;

  check)      # 用 cmp 做逐字节比对，不做任何解析式假设
    mode=$1; N=$2; ok=1
    chk() {  # chk <fileA> <fileB> <label>
      if cmp -s "$1" "$2" 2>/dev/null; then echo "$3: PASS"; else echo "$3: FAIL"; ok=0; fi
    }
    case "$mode" in
      route|transport)
        chk "output-$((N-1)).data" "input-0.data" "rank $((N-1)) $mode (output-$((N-1)).data == input-0.data)" ;;
      shift)
        for ((j=0; j<N; j++)); do p=$(((j-1+N)%N))
          chk "output-$j.data" "input-$p.data" "rank $j shift (output-$j.data == input-$p.data)"
        done ;;
      allreduce)
        for ((j=0; j<N; j++)); do
          chk "output-$j.data" "expected-allreduce.data" "rank $j allreduce (output-$j.data == expected-allreduce.data)"
        done ;;
      *) echo "unknown mode: $mode"; exit 2 ;;
    esac
    [ $ok -eq 1 ] && echo "==> RESULT: PASS" || echo "==> RESULT: FAIL"
    [ $ok -eq 1 ]
    ;;

  *)
    echo "usage: $0 {gen N nints | sum N | check mode N}"; exit 1 ;;
esac
