import sys
import os

# argument_resolver 모듈 경로를 추가
sys.path.append('/home/finder/rev/angr_p/operation-mango-public/package')

from angr import Project
from angr.procedures.definitions.glibc import _libc_decls

# argument_resolver의 핸들러 임포트
from argument_resolver.handlers import handler_factory, StdioHandlers

project = Project('../build/command_line_injection', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True)

_ = project.analyses.CompleteCallingConventions(recover_variables=True)

sink_name = 'system'
sink_function = project.kb.functions.function(name=sink_name)

# 함수 이름과 주소 출력
for function in project.kb.functions.values():
    print(f"function name : {function.name}")
    print(f"function address : {hex(function.addr)}\n")
