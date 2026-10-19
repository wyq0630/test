#!/usr/bin/env python3
"""给 NP2kai 的 pccore.c 打 9821 机型补丁

用法: patch-9821.py <pccore.c 路径>
退出码: 0 成功 / 1 失败
"""
import sys, os

OLD = '''\tmodel = PCMODEL_VX;
\tif (!milstr_cmp(pConfig->model, str_VM)) {
\t\tmodel = PCMODEL_VM;
\t}
\telse if (!milstr_cmp(pConfig->model, str_EPSON)) {
\t\tmodel = PCMODEL_EPSON | PCMODEL_VM;
\t}
\tpccore.model = model;'''

NEW = '''\tmodel = PCMODEL_VX;
\tif (!milstr_cmp(pConfig->model, str_VM)) {
\t\tmodel = PCMODEL_VM;
\t}
\telse if (!milstr_cmp(pConfig->model, str_EPSON)) {
\t\tmodel = PCMODEL_EPSON | PCMODEL_VM;
\t}
#if defined(SUPPORT_PC9821)
\t/* add: 9821 model (upstream defines PCMODEL_PC9821 but never assigns it) */
\telse if (!milstr_cmp(pConfig->model, OEMTEXT("9821"))) {
\t\tmodel = (UINT8)(PCMODEL_PC9821 | PCMODEL_VX);
\t}
#endif
\tpccore.model = model;'''


def main():
    if len(sys.argv) < 2:
        print("用法: patch-9821.py <pccore.c>")
        return 1
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"文件不存在: {path}")
        return 1

    src = open(path, encoding="utf-8", errors="replace").read()
    if "PCMODEL_PC9821 | PCMODEL_VX" in src:
        print("已经打过补丁，跳过")
        return 0
    if OLD not in src:
        print("!! 未找到目标代码，补丁失败（上游可能改过）")
        return 1

    open(path, "w", encoding="utf-8").write(src.replace(OLD, NEW, 1))
    print("OK pccore.c patched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
