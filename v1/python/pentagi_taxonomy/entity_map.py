"""
Auto-generated entity mappings for pentagi-taxonomy.
DO NOT EDIT - this file is generated from entities.yml
"""

from .nodes import Target, Port
from .edges import HasPort, Discovered

ENTITY_TYPES = {
    'Target': Target,
    'Port': Port,
}

EDGE_TYPES = {
    'HAS_PORT': HasPort,
    'DISCOVERED': Discovered,
}

EDGE_TYPE_MAP = {
    ('Target', 'Port'): ['HAS_PORT'],
}
