# Import automatique des tools pour le client Claude
from .nuclei import run as run_nuclei, TOOL_SPEC as nuclei_spec
from .sqlmap import run as run_sqlmap, TOOL_SPEC as sqlmap_spec
from .ffuf import run as run_ffuf, TOOL_SPEC as ffuf_spec
from .recon import run as run_recon, TOOL_SPEC as recon_spec
from .set_phish import run as generate_phish_template, TOOL_SPEC as phish_spec
from .cleanup import run as cleanup_temp, TOOL_SPEC as cleanup_spec

ALL_TOOLS = [nuclei_spec, sqlmap_spec, ffuf_spec, recon_spec, phish_spec, cleanup_spec]
