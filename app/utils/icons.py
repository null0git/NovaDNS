"""Small set of original, minimal line icons rendered as inline SVG so the
whole UI has zero icon-font / CDN dependency."""

_BASE = 'width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"'

ICONS = {
    "grid": f'<svg {_BASE}><rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/></svg>',
    "activity": f'<svg {_BASE}><path d="M2 12h4l3 9 4-18 3 9h6"/></svg>',
    "stethoscope": f'<svg {_BASE}><path d="M5 3v6a4 4 0 0 0 8 0V3"/><path d="M9 13v2a6 6 0 0 0 12 0v-2"/><circle cx="20" cy="19" r="2"/></svg>',
    "globe": f'<svg {_BASE}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
    "shuffle": f'<svg {_BASE}><path d="M3 6h3l8 12h6M3 18h3l3.5-5.3M17 6h4v4M14 8l3.5-2M21 18v-4l-4-4"/></svg>',
    "edit": f'<svg {_BASE}><path d="M4 20l4-1 11-11-3-3L5 16z"/><path d="M14 5l3 3"/></svg>',
    "shield": f'<svg {_BASE}><path d="M12 3l8 3v6c0 4.5-3 7.7-8 9-5-1.3-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    "devices": f'<svg {_BASE}><rect x="3" y="4" width="13" height="9" rx="1"/><path d="M3 17h13"/><rect x="18" y="9" width="4" height="7" rx="1"/></svg>',
    "terminal": f'<svg {_BASE}><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/></svg>',
    "list": f'<svg {_BASE}><path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/></svg>',
    "settings": f'<svg {_BASE}><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg>',
    "menu": f'<svg {_BASE}><path d="M3 6h18M3 12h18M3 18h18"/></svg>',
    "sun-moon": f'<svg {_BASE}><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    "logout": f'<svg {_BASE}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
    "plus": f'<svg {_BASE}><path d="M12 5v14M5 12h14"/></svg>',
    "trash": f'<svg {_BASE}><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
    "check": f'<svg {_BASE}><path d="M4 12l5 5L20 6"/></svg>',
    "x": f'<svg {_BASE}><path d="M5 5l14 14M19 5L5 19"/></svg>',
    "copy": f'<svg {_BASE}><rect x="8" y="8" width="13" height="13" rx="2"/><path d="M4 16V4h12"/></svg>',
    "download": f'<svg {_BASE}><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg>',
    "upload": f'<svg {_BASE}><path d="M12 21V9M7 14l5-5 5 5M4 3h16"/></svg>',
    "refresh": f'<svg {_BASE}><path d="M4 12a8 8 0 0 1 14.7-4.4M20 12a8 8 0 0 1-14.7 4.4M17 3v5h-5M7 21v-5h5"/></svg>',
    "alert-triangle": f'<svg {_BASE}><path d="M12 3l10 18H2z"/><path d="M12 10v4M12 17.5v.1"/></svg>',
    "server": f'<svg {_BASE}><rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/></svg>',
    "cpu": f'<svg {_BASE}><rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M7 3v3M12 3v3M17 3v3M7 18v3M12 18v3M17 18v3M3 7h3M3 12h3M3 17h3M18 7h3M18 12h3M18 17h3"/></svg>',
    "database": f'<svg {_BASE}><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>',
    "lock": f'<svg {_BASE}><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    "bell": f'<svg {_BASE}><path d="M6 9a6 6 0 0 1 12 0c0 5 2 6 2 6H4s2-1 2-6"/><path d="M10 21a2 2 0 0 0 4 0"/></svg>',
    "search": f'<svg {_BASE}><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>',
    "wand": f'<svg {_BASE}><path d="M4 20l10-10M14 4l1.5 1.5M18 8l1.5 1.5M14 10l1.5 1.5M9 5l1.5 1.5"/></svg>',
    "layers": f'<svg {_BASE}><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5M3 8l9 5 9-5"/></svg>',
    "clock": f'<svg {_BASE}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    "wifi": f'<svg {_BASE}><path d="M2 8.5a16 16 0 0 1 20 0M5.5 12a11 11 0 0 1 13 0M9 15.5a6 6 0 0 1 6 0"/><circle cx="12" cy="19" r="1"/></svg>',
}


def icon(name, cls=""):
    svg = ICONS.get(name, "")
    if cls:
        svg = svg.replace("<svg ", f'<svg class="{cls}" ', 1)
    return svg
