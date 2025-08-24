#!/usr/bin/env python
"""Generate V2 test models for advanced evasion testing"""

import os
from pathlib import Path
from create_steganographic_attack_v2 import create_advanced_steganographic_attack, create_baseline_comparison

def main():
    # Create output directory
    assets_dir = Path(__file__).parent.parent / "pickles"
    assets_dir.mkdir(exist_ok=True)
    
    # Generate V2 steganographic attack model
    v2_path = assets_dir / "steganographic_attack_v2.pkl"
    baseline_v2_path = assets_dir / "simple_baseline_v2.pkl"
    
    print("🏭 Generating V2 test models...")
    
    # Create V2 advanced evasion attack
    _, stream1_size, stream2_size = create_advanced_steganographic_attack(str(v2_path))
    print(f"✅ Created: {v2_path}")
    
    # Create baseline for comparison  
    create_baseline_comparison(str(baseline_v2_path))
    print(f"✅ Created: {baseline_v2_path}")
    
    print("\n📁 V2 Test Models Generated:")
    print(f"   - steganographic_attack_v2.pkl ({stream1_size + stream2_size} bytes, 2 streams, advanced evasion)")
    print(f"   - simple_baseline_v2.pkl (single stream, will be detected by both scanners)")

if __name__ == "__main__":
    main()