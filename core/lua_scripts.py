"""
Advanced Scripting Module
NSE-like scripting engine with Lua-like capabilities
"""

import os
import importlib.util
import json
from pathlib import Path
from rich.console import Console

console = Console()

class AdvancedScript:
    """Represents an advanced Nmap-like script"""
    
    def __init__(self, name, description, categories, author="Unknown"):
        self.name = name
        self.description = description
        self.categories = categories if isinstance(categories, list) else [categories]
        self.author = author
        self.metadata = {
            "name": name,
            "description": description,
            "categories": self.categories,
            "author": author,
        }
    
    def __repr__(self):
        return f"Script({self.name})"


class ScriptLibrary:
    """Library of advanced Nmap-style scripts"""
    
    def __init__(self):
        self.scripts = {}
        self.custom_scripts_dir = Path("scripts/")
        self.load_builtin_scripts()
        self.load_custom_scripts()
    
    def register_script(self, script):
        """Register a script"""
        self.scripts[script.name] = script
    
    def load_builtin_scripts(self):
        """Load built-in Nmap-style scripts"""
        builtin_scripts = {
            "ssl-cert": AdvancedScript(
                "ssl-cert",
                "Extracts SSL certificate information",
                ["ssl", "default"],
                "SpectreScan"
            ),
            "http-enum": AdvancedScript(
                "http-enum",
                "Enumerate common HTTP paths",
                ["http", "discovery"],
                "SpectreScan"
            ),
            "smb-os-discovery": AdvancedScript(
                "smb-os-discovery",
                "Enumerate SMB OS information",
                ["smb", "default"],
                "SpectreScan"
            ),
            "dns-brute": AdvancedScript(
                "dns-brute",
                "Perform DNS brute force enumeration",
                ["dns", "discovery"],
                "SpectreScan"
            ),
            "mysql-info": AdvancedScript(
                "mysql-info",
                "Extract MySQL version and info",
                ["mysql", "default"],
                "SpectreScan"
            ),
            "postgres-query": AdvancedScript(
                "postgres-query",
                "Query PostgreSQL for information",
                ["postgres", "database"],
                "SpectreScan"
            ),
            "redis-info": AdvancedScript(
                "redis-info",
                "Retrieve Redis server information",
                ["redis", "database"],
                "SpectreScan"
            ),
        }
        
        for name, script in builtin_scripts.items():
            self.register_script(script)
        
        console.print(f"[green]✓ Loaded {len(builtin_scripts)} built-in scripts[/green]")
    
    def load_custom_scripts(self):
        """Load custom Lua-style scripts from scripts/ directory"""
        if not self.custom_scripts_dir.exists():
            return
        
        for script_file in self.custom_scripts_dir.glob("*.lua"):
            try:
                # Parse Lua script metadata from comments
                with open(script_file, 'r') as f:
                    content = f.read()
                
                # Extract metadata from Lua comments
                metadata = self._parse_lua_metadata(content)
                script = AdvancedScript(
                    name=metadata.get("name", script_file.stem),
                    description=metadata.get("description", "Custom script"),
                    categories=metadata.get("categories", ["custom"]),
                    author=metadata.get("author", "Unknown"),
                )
                self.register_script(script)
            except Exception as e:
                console.print(f"[yellow]Failed to load script {script_file}: {e}[/yellow]")
    
    def _parse_lua_metadata(self, content):
        """Parse Lua script metadata from comments"""
        metadata = {}
        
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('--'):
                # Parse comment metadata like: -- @name script-name
                if '@name' in line:
                    metadata['name'] = line.split('@name')[1].strip()
                elif '@description' in line:
                    metadata['description'] = line.split('@description')[1].strip()
                elif '@categories' in line:
                    cats = line.split('@categories')[1].strip().split(',')
                    metadata['categories'] = [c.strip() for c in cats]
                elif '@author' in line:
                    metadata['author'] = line.split('@author')[1].strip()
        
        return metadata
    
    def get_scripts_by_category(self, category):
        """Get all scripts in a category"""
        return [s for s in self.scripts.values() if category in s.categories]
    
    def get_scripts_by_port(self, port):
        """Get scripts that typically run on a port"""
        port_categories = {
            22: ["ssh"],
            25: ["smtp"],
            53: ["dns"],
            80: ["http"],
            110: ["pop3"],
            143: ["imap"],
            443: ["https", "ssl"],
            445: ["smb"],
            3306: ["mysql"],
            5432: ["postgres"],
            6379: ["redis"],
            27017: ["mongodb"],
        }
        
        categories = port_categories.get(port, [])
        scripts = []
        for cat in categories:
            scripts.extend(self.get_scripts_by_category(cat))
        
        return scripts
    
    def list_scripts(self):
        """List all available scripts"""
        table_data = []
        for script in self.scripts.values():
            table_data.append({
                "name": script.name,
                "description": script.description,
                "categories": ", ".join(script.categories),
            })
        
        return table_data
    
    def execute_script(self, script_name, target, port, *args, **kwargs):
        """
        Execute a script
        In production, this would invoke Lua interpreter
        """
        if script_name not in self.scripts:
            console.print(f"[red]Script not found: {script_name}[/red]")
            return None
        
        script = self.scripts[script_name]
        console.print(f"[cyan]Executing: {script.name}[/cyan]")
        
        # Return script execution result
        return {
            "script": script_name,
            "target": target,
            "port": port,
            "result": "Script execution simulated",
        }


# Global script library instance
script_library = ScriptLibrary()
