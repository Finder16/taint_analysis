import sys
import os

# argument_resolver 모듈 경로를 추가
sys.path.append('/home/finder/rev/angr_p/package')
from argument_resolver.utils.utils import Utils
from argument_resolver.utils.rda import CustomRDA
from argument_resolver.utils.call_trace import traces_to_sink
from argument_resolver.utils.call_trace_visitor import CallTraceSubject


from angr import Project
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.procedures.definitions.glibc import _libc_decls
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE
from angr.analyses.analysis import AnalysisFactory
from angr.knowledge_plugins.key_definitions.atoms import Register


# Local handy function to print a graph to a file.
from utils import magic_graph_print as m_g_p
magic_graph_print = lambda dependencies: m_g_p(os.path.basename(__file__)[:-3], dependencies)

from argument_resolver.handlers import handler_factory, StdioHandlers


def subject_from_function(roject, function, depth=1):
    traces = traces_to_sink(function, project.kb.functions.callgraph, depth, [])

    trace = traces.pop()
    function_address = trace.current_function_address()
    init_function = project.kb.functions[function_address]
    return CallTraceSubject(trace, init_function)

project = Project('build/buffer_overflow_strcpy', auto_load_libs=False)
cfg = project.analyses.CFGFast(normalize=True, data_references=True)

_ = project.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg)

Handler = handler_factory([
    StdioHandlers,
])


sink = project.kb.functions.function(name="strcpy")
observation_points = set(Utils.get_all_callsites(project))
subject = subject_from_function(project, sink)
handler = Handler(project, sink, [Register(*project.arch.registers["rsi"])])

RDA = AnalysisFactory(project, CustomRDA)

rda = RDA(
            subject=subject,
            observation_points=observation_points,
            function_handler=handler,
            dep_graph=DepGraph(),
)

results = handler.analyzed_list[-1].state
print(handler.analyzed_list)

