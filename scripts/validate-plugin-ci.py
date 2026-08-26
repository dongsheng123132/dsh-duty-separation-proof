#!/usr/bin/env python3
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]; data = json.loads((root / '.codex-plugin' / 'plugin.json').read_text(encoding='utf-8')); required = {'name', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'interface', 'mcpServers'}; missing = sorted(required - data.keys())
if missing: raise SystemExit(f'missing plugin fields: {missing}')
if data['mcpServers'] != './.mcp.json': raise SystemExit('mcpServers must reference ./.mcp.json')
print(json.dumps({'ok': True, 'plugin': data['name'], 'version': data['version']}))
