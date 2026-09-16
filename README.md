# 中药不良反应信号核查

该项目整理病例首报、随访、产品暴露和调查记录。患者匹配标识与可识别信息分开保存，疑似重复只作为人工核查线索。

`safety/contracts.py` 提供病例和信号类型，`fixtures/adverse_reports.json` 包含跨机构转院与缺失批号的脱敏报告。运行 `python -m compileall safety` 可在 Python 3.11 下检查契约。
