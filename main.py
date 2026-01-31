import sys
import time
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.align import Align
from rich.style import Style
from rich import box
from devices import DeviceManager
from sniffer import PassiveSniffer
from active_scanner import ActiveScanner
from network_discovery import get_scannable_networks, detect_vpn_connections
from classifier import classify_device, get_device_icon, get_device_label, DEVICE_CAMERA, is_camera_confident, get_confidence_label
import scapy.all as scapy

console = Console()

# ASCII Art Logo
LOGO = """
[bold cyan]
    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]
[dim]────────────────── Network Asset Discovery Tool ──────────────────[/dim]
[bold yellow]                    🔍 Passive • Active • Hybrid 🔍[/bold yellow]
"""

MINI_LOGO = "[bold cyan]◈ NETSCAN[/bold cyan]"


def animate_startup():
    """Display animated startup sequence."""
    frames = [
        "[dim]Initializing[/dim] .",
        "[dim]Initializing[/dim] ..",
        "[dim]Initializing[/dim] ...",
        "[cyan]Loading modules[/cyan] .",
        "[cyan]Loading modules[/cyan] ..",
        "[cyan]Loading modules[/cyan] ...",
        "[green]Ready[/green] ✓",
    ]
    
    console.print(LOGO)
    
    for frame in frames:
        console.print(f"\r{frame}", end="")
        time.sleep(0.15)
    
    console.print("\n")


def get_interfaces():
    """Get list of available network interfaces."""
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except:
        return []


def select_interface():
    """Display interface selection menu."""
    interfaces = get_interfaces()
    
    if not interfaces:
        console.print("[yellow]⚠ No interfaces found. Using default.[/yellow]")
        return None
    
    console.print(Panel(
        "\n".join([f"  [green]{i}[/green]. {iface}" for i, iface in enumerate(interfaces, 1)]) +
        f"\n  [green]0[/green]. Auto-detect (default)",
        title="[bold cyan]📡 Network Interfaces[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))
    
    while True:
        try:
            choice = console.input("\n[bold cyan]►[/bold cyan] Select interface [bold][0][/bold]: ") or "0"
            choice = int(choice)
            if choice == 0:
                return None
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            console.print("[red]✗ Invalid choice.[/red]")
        except ValueError:
            console.print("[red]✗ Please enter a number.[/red]")
        except KeyboardInterrupt:
            sys.exit(0)


def select_mode():
    """Display scan mode selection menu."""
    modes = """
  [green]1[/green]. [dim]🔇[/dim] [bold]Passive[/bold]     [dim]─ Single network, listen-only[/dim]
  [green]2[/green]. [dim]📡[/dim] [bold]Active[/bold]      [dim]─ Single network, ARP + port scan[/dim]
  [green]3[/green]. [dim]⚡[/dim] [bold]Hybrid[/bold]      [dim]─ Single network, Active + Passive [bold](recommended)[/bold][/dim]
  [green]4[/green]. [dim]🌐[/dim] [bold]Multi-Net[/bold]   [dim]─ Scan ALL detected networks[/dim]
  [green]5[/green]. [dim]🔒[/dim] [bold]VPN Watch[/bold]   [dim]─ Monitor for VPN usage[/dim]
"""
    
    console.print(Panel(
        modes,
        title="[bold cyan]🎯 Scan Mode[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))
    
    while True:
        try:
            choice = console.input("\n[bold cyan]►[/bold cyan] Select mode [bold][3][/bold]: ") or "3"
            choice = int(choice)
            if choice in [1, 2, 3, 4, 5]:
                return choice
            console.print("[red]✗ Invalid choice.[/red]")
        except ValueError:
            console.print("[red]✗ Please enter a number.[/red]")
        except KeyboardInterrupt:
            sys.exit(0)


def format_time_ago(timestamp):
    """Format timestamp as 'X ago' string."""
    if not timestamp:
        return "-"
    
    diff = time.time() - timestamp
    if diff < 60:
        return f"{int(diff)}s"
    elif diff < 3600:
        return f"{int(diff / 60)}m"
    else:
        return f"{int(diff / 3600)}h"


def create_device_table(devices):
    """Create a rich table with device information."""
    table = Table(
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="bright_blue",
        expand=True,
        padding=(0, 1)
    )
    
    table.add_column("IP", style="bright_green", width=14, justify="left")
    table.add_column("MAC", style="dim", width=17)
    table.add_column("TYPE", justify="center", width=14)
    table.add_column("CONF", justify="center", width=5)
    table.add_column("VENDOR", style="yellow", width=12, overflow="ellipsis")
    table.add_column("NAME", style="cyan", width=14, overflow="ellipsis")
    table.add_column("SERVICES", style="blue", width=14, overflow="ellipsis")
    table.add_column("⏱", justify="center", width=4)
    
    # Sort by IP address
    sorted_devices = sorted(devices, key=lambda d: d.ip if d.ip else "255.255.255.255")
    
    camera_count = 0
    
    for device in sorted_devices:
        ip = device.ip or "[dim]Unknown[/dim]"
        vendor = (device.vendor[:12] if device.vendor else "[dim]-[/dim]")
        
        # Classify device with confidence
        result = classify_device(device)
        device_type = result.device_type
        confidence = result.confidence
        icon = get_device_icon(device_type)
        label = get_device_label(device_type)
        
        # Confidence styling
        if confidence >= 80:
            conf_str = f"[bold green]{confidence}%[/bold green]"
        elif confidence >= 60:
            conf_str = f"[yellow]{confidence}%[/yellow]"
        elif confidence >= 40:
            conf_str = f"[dim]{confidence}%[/dim]"
        else:
            conf_str = f"[dim red]{confidence}%[/dim red]"
        
        # Check for camera with high confidence (>=70%)
        is_camera = is_camera_confident(device, threshold=70)
        if is_camera:
            type_str = f"[bold red]{icon} {label}[/bold red]"
            camera_count += 1
        else:
            type_str = f"{icon} {label}"
        
        # Hostnames
        name = ", ".join(list(device.hostnames)[:1])[:14] if device.hostnames else "[dim]-[/dim]"
        
        # Services
        if device.services:
            svc_list = [s for s in list(device.services)[:2] if "CAMERA_DETECTED" not in s]
            services = ", ".join([s[:7] for s in svc_list])
            if len(device.services) > 2:
                services += f" +{len(device.services) - 2}"
        else:
            services = "[dim]-[/dim]"
        
        last_seen = format_time_ago(device.last_seen)
        
        # Highlight row for cameras
        if is_camera:
            table.add_row(
                f"[bold red]{ip}[/bold red]", device.mac, type_str, conf_str, vendor, name, services, last_seen,
                style="on dark_red"
            )
        else:
            table.add_row(ip, device.mac, type_str, conf_str, vendor, name, services, last_seen)
    
    return table, camera_count


def run_active_scan(device_manager, progress_console):
    """Run comprehensive active scan with multiple phases."""
    scanner = ActiveScanner(device_manager)
    
    console.print()
    console.print("[bold cyan]Starting comprehensive network scan...[/bold cyan]\n")
    
    with Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=30, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        console=progress_console,
        transient=False
    ) as progress:
        # Phase 1: ARP Sweep
        task1 = progress.add_task("🔍 Phase 1: ARP Sweep (2 retries)...", total=100)
        
        for i in range(0, 60, 15):
            time.sleep(0.1)
            progress.update(task1, completed=i)
        
        arp_count = scanner.full_discovery()
        progress.update(task1, completed=100, description=f"[green]✓ ARP Sweep: {arp_count} devices[/green]")
        
        # Phase 2: Port Scanning
        devices = device_manager.get_all_devices()
        ips = [d.ip for d in devices if d.ip and d.ip != "Unknown"]
        
        if ips:
            task2 = progress.add_task(f"🔌 Phase 2: Port Scan ({len(ips)} hosts, 25+ ports)...", total=len(ips))
            
            def update_port_progress(current, total):
                progress.update(task2, completed=current)
            
            port_results = scanner.deep_scan(
                progress_callback=lambda t, p, c, tot: progress.update(task2, completed=c, description=f"🔌 Phase 2: {p} ({c}/{tot})")
            )
            
            progress.update(task2, completed=len(ips), description=f"[green]✓ Port Scan Complete[/green]")
            
            # Phase 3: Camera Detection
            task3 = progress.add_task("📷 Phase 3: Camera Detection...", total=100)
            
            camera_count = port_results.get("camera_count", 0)
            
            for i in range(0, 101, 25):
                time.sleep(0.05)
                progress.update(task3, completed=i)
            
            if camera_count > 0:
                progress.update(task3, completed=100, description=f"[bold red]⚠️ {camera_count} camera(s) found![/bold red]")
            else:
                progress.update(task3, completed=100, description="[green]✓ No cameras detected[/green]")
    
    # Summary
    total_devices = len(device_manager.get_all_devices())
    console.print(f"\n[bold green]✓ Scan Complete: {total_devices} devices discovered[/bold green]")
    
    # Show open ports summary
    devices = device_manager.get_all_devices()
    with_ports = [d for d in devices if any(s.startswith("Port:") for s in d.services)]
    if with_ports:
        console.print(f"[dim]  └─ {len(with_ports)} devices with open ports[/dim]\n")


def export_to_json(devices, filename):
    """Export devices to JSON file."""
    data = []
    for d in devices:
        result = classify_device(d)
        data.append({
            "mac": d.mac,
            "ip": d.ip,
            "vendor": d.vendor,
            "hostnames": list(d.hostnames),
            "services": list(d.services),
            "os_guess": d.os_guess,
            "device_type": result.device_type,
            "confidence": result.confidence,
            "confidence_level": get_confidence_label(result.confidence),
            "signals": result.signals,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen
        })
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    return filename


def export_to_csv(devices, filename):
    """Export devices to CSV file."""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["MAC", "IP", "Vendor", "Type", "Confidence", "Hostnames", "Services", "OS", "First Seen", "Last Seen"])
        for d in devices:
            result = classify_device(d)
            writer.writerow([
                d.mac,
                d.ip or "",
                d.vendor or "",
                result.device_type,
                f"{result.confidence}%",
                "|".join(d.hostnames),
                "|".join(d.services),
                d.os_guess or "",
                datetime.fromtimestamp(d.first_seen).isoformat() if d.first_seen else "",
                datetime.fromtimestamp(d.last_seen).isoformat() if d.last_seen else ""
            ])
    return filename


def run_multi_network_scan(device_manager, progress_console):
    """
    Scan ALL detected networks including VPNs.
    Fully automatic - no technical knowledge required.
    """
    console.print("\n[bold cyan]🌐 Multi-Network Scan Mode[/bold cyan]")
    console.print("[dim]Automatically detecting all networks...[/dim]\n")
    
    # Detect all networks
    networks = get_scannable_networks()
    vpns = detect_vpn_connections()
    
    if not networks:
        console.print("[red]✗ No networks detected![/red]")
        return
    
    # Display detected networks
    network_list = "\n".join([
        f"  {net['icon']} [bold]{net['name'][:35]}[/bold]\n"
        f"     [dim]Subnet: {net['subnet']}[/dim]"
        for net in networks
    ])
    
    console.print(Panel(
        network_list,
        title=f"[bold cyan]📡 Detected {len(networks)} Network(s)[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))
    
    # Show VPN status
    if vpns:
        console.print(f"[bold green]🔒 Active VPN(s): {len(vpns)}[/bold green]")
        for vpn in vpns:
            console.print(f"   └─ {vpn['name']}: {vpn['ip']}")
    else:
        console.print("[dim]🔓 No VPN connections detected[/dim]")
    
    console.print()
    
    # Scan each network
    total_devices = 0
    
    with Progress(
        SpinnerColumn(spinner_name="dots12", style="cyan"),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=30, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        console=progress_console,
        transient=False
    ) as progress:
        
        for i, net in enumerate(networks):
            task = progress.add_task(
                f"{net['icon']} Scanning {net['name'][:25]}...",
                total=100
            )
            
            try:
                # Create scanner for this specific subnet
                from active_scanner import arp_scan, parallel_port_scan, parallel_hostname_resolve
                
                # ARP scan this subnet
                progress.update(task, completed=20, description=f"{net['icon']} ARP: {net['subnet']}")
                results = arp_scan(net['subnet'], timeout=2, retry=1)
                
                progress.update(task, completed=40, description=f"{net['icon']} Found {len(results)} devices")
                
                # Add devices to manager
                for ip, mac in results:
                    device_manager.update_device(mac, ip=ip)
                    # Tag with network name
                    device_manager.update_device(mac, service=f"Net:{net['type']}")
                
                # Resolve hostnames (CRITICAL for Windows PC detection)
                if results:
                    ips = [ip for ip, mac in results]
                    progress.update(task, completed=50, description=f"{net['icon']} Resolving names...")
                    hostnames = parallel_hostname_resolve(ips, max_workers=10)
                    
                    for ip, hostname in hostnames.items():
                        # Find device by IP and add hostname
                        for device in device_manager.get_all_devices():
                            if device.ip == ip:
                                device.add_hostname(hostname)
                                break
                
                # Quick port scan on discovered devices
                if results:
                    ips = [ip for ip, mac in results]
                    camera_ports = [554, 8554, 37777, 80, 443]
                    
                    progress.update(task, completed=75, description=f"{net['icon']} Port scan...")
                    port_results = parallel_port_scan(ips, ports=camera_ports, max_workers=10)
                    
                    for ip, ports in port_results.items():
                        # Find device and add services
                        for device in device_manager.get_all_devices():
                            if device.ip == ip:
                                for port, name in ports:
                                    device.add_service(f"Port:{port}({name})")
                                    if port in [554, 8554, 37777]:
                                        device.add_service("⚠️ CAMERA_SUSPECTED")
                
                total_devices += len(results)
                progress.update(
                    task, 
                    completed=100, 
                    description=f"[green]✓ {net['name'][:25]}: {len(results)} devices[/green]"
                )
                
            except Exception as e:
                progress.update(
                    task, 
                    completed=100, 
                    description=f"[yellow]⚠ {net['name'][:25]}: Error[/yellow]"
                )
    
    console.print(f"\n[bold green]✓ Multi-Network Scan Complete: {total_devices} total devices[/bold green]\n")


def main():
    # Animated startup
    animate_startup()
    # Mode selection
    mode = select_mode()
    mode_names = {
        1: "🔇 Passive", 
        2: "📡 Active", 
        3: "⚡ Hybrid", 
        4: "🌐 Multi-Net",
        5: "🔒 VPN Watch"
    }
    console.print(f"\n[bold green]✓[/bold green] Mode: [bold]{mode_names[mode]}[/bold]")
    
    device_manager = DeviceManager()
    sniffer = None
    interface = None
    
    # Mode 1 (Passive): Single network, listen only
    if mode == 1:
        interface = select_interface()
        if interface:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]{interface}[/bold]")
        else:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]Auto-detect[/bold]")
        
        sniffer = PassiveSniffer(device_manager, interface=interface, enable_vpn_detection=False)
        console.print("[yellow]◈ Starting passive listener...[/yellow]")
        sniffer.start()
        console.print("[green]◈ Listening for network traffic[/green]\n")
    
    # Mode 2 (Active): Single network, ARP + port scan
    elif mode == 2:
        interface = select_interface()
        if interface:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]{interface}[/bold]")
        else:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]Auto-detect[/bold]")
        
        console.print(Panel("[bold]Running active scan...[/bold]", border_style="yellow"))
        run_active_scan(device_manager, console)
    
    # Mode 3 (Hybrid): Single network, Active + Passive (RECOMMENDED)
    elif mode == 3:
        interface = select_interface()
        if interface:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]{interface}[/bold]")
        else:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]Auto-detect[/bold]")
        
        # First: Active scan
        console.print(Panel("[bold]Running active scan...[/bold]", border_style="yellow"))
        run_active_scan(device_manager, console)
        
        # Then: Passive listening (no VPN detection in Hybrid)
        sniffer = PassiveSniffer(device_manager, interface=interface, enable_vpn_detection=False)
        console.print("[yellow]◈ Starting passive listener...[/yellow]")
        sniffer.start()
        console.print("[green]◈ Listening for network traffic[/green]\n")
    
    # Mode 4 (Multi-Net): Scan ALL detected networks
    elif mode == 4:
        console.print()  # No interface selection needed
        run_multi_network_scan(device_manager, console)
    
    # Mode 5 (VPN Watch): Monitor for VPN usage only
    elif mode == 5:
        interface = select_interface()
        if interface:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]{interface}[/bold]")
        else:
            console.print(f"[bold green]✓[/bold green] Interface: [bold]Auto-detect[/bold]")
        
        console.print("\n[bold cyan]🔒 VPN Watch Mode[/bold cyan]")
        console.print("[dim]Monitoring network traffic for VPN usage...[/dim]")
        console.print("[dim]Detected VPN protocols: OpenVPN, WireGuard, IKEv2, L2TP, PPTP[/dim]\n")
        
        # Start passive sniffer with VPN detection ONLY
        sniffer = PassiveSniffer(device_manager, interface=interface, enable_vpn_detection=True)
        sniffer.start()
        console.print("[green]◈ Monitoring for VPN traffic...[/green]\n")
    
    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            while True:
                devices = device_manager.get_all_devices()
                table, camera_count = create_device_table(devices)
                
                # Create status bar
                status = Text()
                status.append(f" 📡 {len(devices)} ", style="bold white on dark_green")
                status.append(" devices ", style="bold green")
                
                if camera_count > 0:
                    status.append(f" 📷 {camera_count} ", style="bold white on red")
                    status.append(" cameras ", style="bold red")
                
                status.append(" │ ", style="dim")
                status.append("Ctrl+C", style="bold dim")
                status.append(" to stop ", style="dim")
                
                # Wrap table in panel
                panel = Panel(
                    table,
                    title=f"{MINI_LOGO} [dim]Network Asset Discovery[/dim]",
                    subtitle=status,
                    border_style="bright_blue",
                    padding=(0, 1)
                )
                
                live.update(panel)
                time.sleep(0.5)
                
    except KeyboardInterrupt:
        console.print("\n[yellow]◈ Stopping...[/yellow]")
        if sniffer:
            sniffer.stop()
        
        devices = device_manager.get_all_devices()
        if devices:
            # Check for cameras with high confidence (>=70%)
            camera_devices = [d for d in devices if is_camera_confident(d, threshold=70)]
            
            if camera_devices:
                cam_lines = []
                for cam in camera_devices:
                    result = classify_device(cam)
                    cam_lines.append(f"  📷 [red]{cam.ip}[/red] ({cam.vendor}) - [bold]{result.confidence}% confidence[/bold]")
                console.print(Panel(
                    "\n".join(cam_lines),
                    title=f"[bold red]⚠️  PRIVACY ALERT: {len(camera_devices)} Camera(s) Detected[/bold red]",
                    border_style="red"
                ))
            
            console.print(Panel(
                "  [green]1[/green]. Export to JSON\n  [green]2[/green]. Export to CSV\n  [green]0[/green]. Skip",
                title=f"[bold cyan]📁 Export {len(devices)} devices?[/bold cyan]",
                border_style="cyan"
            ))
            
            try:
                choice = console.input("[bold cyan]►[/bold cyan] Choice [bold][0][/bold]: ") or "0"
                if choice == "1":
                    filename = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    export_to_json(devices, filename)
                    console.print(f"[green]✓ Saved to {filename}[/green]")
                elif choice == "2":
                    filename = f"netscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    export_to_csv(devices, filename)
                    console.print(f"[green]✓ Saved to {filename}[/green]")
            except:
                pass
        
        console.print("\n[bold green]◈ NETSCAN Complete[/bold green]\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
