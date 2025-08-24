#!/usr/bin/env python
"""Generate V3 test models for perfect invisibility testing"""

import os
from pathlib import Path
from create_steganographic_attack_v3 import create_perfect_steganographic_attack, create_control_attack

def main():
    # Create output directory
    assets_dir = Path(__file__).parent.parent / "pickles"
    assets_dir.mkdir(exist_ok=True)
    
    # Generate V3 perfect steganographic attack model
    v3_path = assets_dir / "steganographic_attack_v3.pkl"
    control_v3_path = assets_dir / "control_attack_v3.pkl"
    
    print("🏭 Generating V3 test models...")
    
    # Create V3 perfect invisibility attack
    _, stream1_size, stream2_size = create_perfect_steganographic_attack(str(v3_path))
    print(f"✅ Created: {v3_path}")
    
    # Create control for comparison  
    create_control_attack(str(control_v3_path))
    print(f"✅ Created: {control_v3_path}")
    
    print("\n📁 V3 Test Models Generated:")
    print(f"   - steganographic_attack_v3.pkl ({stream1_size + stream2_size} bytes, 2 streams, perfect invisibility)")
    print(f"   - control_attack_v3.pkl (single stream, WILL be detected by both scanners)")

if __name__ == "__main__":
    main()