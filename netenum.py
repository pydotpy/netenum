import subprocess
import os.path
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN


class Dependencies:
    """ensures dependencies are installed"""

    def __init__(self, app_dir, app):
        self.app_dir = app_dir
        self.app = app

    def check_directory(self):
        check_dir = self.app_dir + self.app
        if os.path.exists(check_dir):
            print(Fore.GREEN + self.app_dir + self.app, "located.")
            print()
        else:
            self.verify()

    def verify(self):
        verify_app = input(self.app + ' is not installed. Would you like to '
                                      'install it? y/n ' + '\n')

        if verify_app == 'y'.lower():
            self.install_app()

        elif verify_app == 'n'.lower():
            self.close()
        else:
            print('Invalid entry. Use y to install', self.app, 'or n to exit. Ensure Caps lock is off.'
                  + '\n')
            self.check_directory()

    def install_app(self):
        print('installing', self.app, '...')
        subprocess.run(["sudo", "apt-get", "install", self.app])

    def close(self):
        print('Exiting...')
        exit()


class TargetType:
    """User selects a target type"""

    def __init__(self, target_type):
        self.target_type = target_type

    def display_target_type(self):
        target_type_list = ['{0}domain'. format(yellow), '{0}network device'.format(yellow)]
        for index, item in enumerate(target_type_list, start=1):
            print(index, item)
        self.select_target_type()

    def select_target_type(self):
        while True:
            try:
                user_input = int(input("Select a " + self.target_type + ": "))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if user_input > 2:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if user_input == 1 or 2:
            select_target = CustomScan()
            select_target.select_target()
        else:
            self.select_target_type()


class CustomScan:
    """
       Class that generates a custom scan. All instances are appended to
       the scan_option_selections list and plugged into subprocess.run()
       in the self.scan()
    """

    def __init__(self, target=None, int_level=None, ports=None, so1=None, so2=None, so3=None, zombie=None, decoy=None, spoof_ip=None,
                 spoof_port=None, mac=None, badsum=None):
        self.target = target  # target device or domain
        self.int_level = int_level  # intensity level
        self.ports = ports  # port(s) or port range
        self.so1 = so1  # scan option 1
        self.s02 = so2  # scan option 2
        self.so3 = so3  # scan option 3
        self.zombie = zombie
        self.decoy = decoy  # decoy(s)
        self.spoof_ip = spoof_ip  # spoofed source IP address
        self.spoof_port = spoof_port  # spoofed source port
        self.mac = mac  # spoofed MAC address (randomized)
        self.badsum = badsum  # an invalid checksum
        self.scan_option_selections = []  # a list of all selected options
        self.scan_option_selections.append('nmap')
        self.scan_option_selections.append('-vv')

    def select_target(self):
        """User selects a target type (domain or network device)"""

        self.target = input('Select {0}target{1}: '.format(yellow, reset))
        print()
        if self.target == '':
            self.select_target()
        else:
            self.select_intensity()

    def select_intensity(self):
        """User selects an intensity level from -T0 to -T5"""

        intensity_options = ['{0} -T0 {1}= Paranoid (Intrusion Detection System evasion)'.format(yellow, reset),
                             '{0} -T1 {1}= Sneaky (Intrusion Detection System evasion)'.format(yellow, reset),
                             '{0} -T2 {1}= Polite (less bandwidth and target system resources)'.format(yellow, reset),
                             '{0} -T3 {1}= Normal (default speed)'.format(yellow, reset),
                             '{0} -T4 {1}= Aggressive (Assumes you are on a reasonably fast and reliable network)'.format(yellow, reset),
                             '{0} -T5 {1}= Insane (Assumes you are on an extraordinarily fast network)'.format(yellow, reset)]

        for index, item in enumerate(intensity_options, start=1):
            print(index, item)

        while True:
            try:
                intensity_input = int(input("Select an " + yellow + "intensity level "
                                       + reset + "from 1-{}: ".format(len(intensity_options))))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if intensity_input > 6:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if intensity_input == 1:
            self.int_level = '-T0'  # paranoid
        elif intensity_input == 2:
            self.int_level = '-T1'  # sneaky
        elif intensity_input == 3:
            self.int_level = '-T2'  # polite
        elif intensity_input == 4:
            self.int_level = '-T3'  # Normal
        elif intensity_input == 5:
            self.int_level = '-T4'  # Aggressive
        elif intensity_input == 6:
            self.int_level = '-T5'  # Insane

        self.scan_option_selections.append(self.int_level)
        self.select_ports()

    def select_ports(self):
        """User selects port probing options"""

        port_options = [yellow + 'all ports ' + reset + 'on ' + self.target,
                        yellow + 'common ports ' + reset + 'on ' + self.target,
                        yellow + 'specific ports ' + reset + 'on ' + self.target,
                        yellow + 'port range ' + reset + 'on ' + self.target]

        for index, item in enumerate(port_options, start=1):
            print(index, item)

        while True:
            try:
                port_input = int(input("Select your " + yellow + "port probing option " + reset + "from 1-{}: "
                                       .format(len(port_options))))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if port_input > 4:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if port_input == 1:
            self.ports = '-p-'  # all ports
            self.scan_option_selections.append(self.ports)
            self.display_scan_techniques()
        elif port_input == 2:
            self.ports = '-F'  # common ports
            self.scan_option_selections.append(self.ports)
            self.display_scan_techniques()
        elif port_input == 3:
            self.additional_port_options()  # So user can specify what exactly they need
        elif port_input == 4:
            self.additional_port_options()  # So user can specify what exactly they need

    def additional_port_options(self):
        """User selects specific port probing options"""

        print("You can scan single TCP or UDP ports using the format {0}-p 22{1}, {0}-p 80{1}, or {0}-pU:53{1}. "
              "{2}Or, you can scan a single a port range, such as {0}-p 1-1000".format(yellow, reset, '\n'))
        print()

        self.ports = input("Please specify ports to scan using the {0}syntax {1}above: ".format(yellow, reset))
        print()
        if self.ports == '':
            print("{0}That's not a valid option. Did you follow the syntax? Or press 'b' to go back".format(red))
            self.additional_port_options()
        elif self.ports.lower() == 'b':
            self.select_ports()
        elif not self.ports.startswith('-p '):  # input validation
            print("{0}That's not a valid option. Did you follow the syntax? or press 'b' to go back".format(red))
            self.additional_port_options()
        else:
            self.scan_option_selections.append(self.ports)
            self.display_scan_techniques()

    def display_scan_techniques(self):
        """display all TCP scan techniques """

        global scan_options
        scan_options = ['{0}-sT {1}= TCP Connect'.format(yellow, reset),
                        '{0}-sS {1}= SYN Stealth'.format(yellow, reset),
                        '{0}-sN {1}= Null'.format(yellow, reset),
                        '{0}-sF {1}= FIN'.format(yellow, reset),
                        '{0}-sA {1}= ACK'.format(yellow, reset),
                        '{0}-sX {1}= XMAS'.format(yellow, reset),
                        '{0}-b {1}= FTP Bounce {2}(WARNING: DO NOT USE. FEATURE STILL BEING TESTED'.format(yellow, reset, red),
                        '{0}-sI {1}= Idle {2}(Must specify a zombie host)'.format(yellow, reset, Fore.LIGHTYELLOW_EX),
                        '{0}-sM {1}= Maimon'.format(yellow, reset),
                        '{0}-sW {1}= TCP Window'.format(yellow, reset)]

        for index, item in enumerate(scan_options, start=1):
            print(index, item)
        self.select_scan_option_1()

    def select_scan_option_1(self):
        """User selects a TCP scan technique"""

        while True:
            try:
                so1_input = int(input("Select a TCP scan technique from values 1-{}: ".format(len(scan_options))))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if so1_input > 10:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if so1_input == 1:
            self.so1 = '-sT'  # TCP Connect Scan
        elif so1_input == 2:
            self.so1 = '-sS'  # SYN Stealth Scan
        elif so1_input == 3:
            self.so1 = '-sN'  # Null Scan
        elif so1_input == 4:
            self.so1 = '-sF'  # FIN Scan
        elif so1_input == 5:
            self.so1 = '-sA'  # ACK Scan
        elif so1_input == 6:
            self.so1 = '-sX'  # XMAS Scan
        elif so1_input == 7:
            # self.so1 = '-b'  # FTP Bounce Scan
            self.select_scan_option_1()
        elif so1_input == 8:
            self.select_zombie()  # Idle Scan
        elif so1_input == 9:
            self.so1 = '-sM'  # Maimon Scan
        elif so1_input == 10:
            self.so1 = '-sW'  # TCP Window Scan

        self.scan_option_selections.append(self.so1)
        self.select_scan_option_2()

    def select_zombie(self):
        """User selects a zombie host if they selected an Idle Scan"""

        self.zombie = input("specify a {0}zombie {1} to use. or press 'b' to go back: ".format(yellow, reset))
        if self.zombie == '':
            print(("{0}That's not a valid option. Try again. Or, press 'b' to go back".format(red)))
            self.select_zombie()
        elif self.zombie.lower() == 'b':
            self.display_scan_techniques()
        else:
            self.so1 = '-sI'  # Idle Scan
            self.scan_option_selections.append('-Pn')
            self.scan_option_selections.append(self.so1)
            self.scan_option_selections.append(self.zombie)
            print()
            self.select_scan_option_2()

    def select_scan_option_2(self):
        """User selects an additional scan option, if desired"""

        global alt_scan_options
        alt_scan_options = ['{0}-sU {1}= UDP port'.format(yellow, reset),
                            '{0}-O {1}= OS Detection'.format(yellow, reset)]

        answer = input('Would you like to stack a {0}second scan option{1}? [y/n]: '.format(yellow, reset))
        print()

        if answer.lower() == 'n':
            self.select_scan_option_3()
        elif answer.lower() == 'y':
            for index, item in enumerate(alt_scan_options, start=1):
                print(index, item)
        else:
            self.select_scan_option_2()

        while True:
            try:
                so2_input = int(input("Select a scan technique from 1-{}: ".format(len(alt_scan_options))))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if so2_input > 2:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if so2_input == 1:
            self.so2 = '-sU'
        elif so2_input == 2:
            self.so2 = '-O'

        self.scan_option_selections.append(self.so2)
        self.select_scan_option_3()

    def select_scan_option_3(self):
        """User selects version detection, if desired"""

        version_input = input("include {0}version detection {1}in your scan? [y/n]: ".format(yellow, reset))
        print()
        if version_input.lower() == 'y':
            self.so3 = '-sV'
            self.scan_option_selections.append(self.so3)
        elif version_input.lower() == 'n':
            self.firewall_spoof_options()
        else:
            print("{0}That's not a valid option.".format(red))
            self.select_scan_option_3()
        self.firewall_spoof_options()

    def firewall_spoof_options(self):
        """User chooses firewall evasion or spoofing options, if desired"""

        answer = input("include {0}firewall and IDS evasion or spoofing {1}to your scan? [y/n]: ".format(yellow, reset))
        print()
        if answer.lower() == 'n':
            self.scan()
        elif answer.lower() == 'y':
            self.select_firewall_spoof_options()
        else:
            self.firewall_spoof_options()

    def select_firewall_spoof_options(self):
        """User selects firewall evasion and spoofing options"""

        firewall_spoof_list = ['{0}-D {1}= Decoy Cloaking'.format(yellow, reset),
                               '{0}-S {1}= Spoof Source Address {2}(WARNING: DO NOT USE. FEATURE IS STILL BEING TESTED)'.format(yellow, reset, red),
                               '{0}--source-port {1}= Spoof Source Port Number'.format(yellow, reset),
                               '{0}--spoof-mac {1}= Spoof MAC Address {2}(WARNING: DO NOT USE. FEATURE IS STILL BEING TESTED)'.format(yellow, reset, red),
                               '{0}--badsum {1}= Send Bogus TCP/UDP checksums'.format(yellow, reset)]

        for index, item in enumerate(firewall_spoof_list, start=1):
            print(index, item)

        while True:
            try:
                print()
                user_input = int(input("Select a firewall evasion or spoofing option from 1-{}: ".format(len(firewall_spoof_list))))
                print()
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if user_input > 5:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if user_input == 1:
            self.decoy_cloaking()
        elif user_input == 2:
            self.select_firewall_spoof_options()
        elif user_input == 3:
            try:
                if self.so1 == '-sT' or self.so2 == '-O' or self.so3 == '-sV':
                    print("{0}RETURNING:".format(red))  # display precaution and return to self.select_firewall_spoof_options()
                    print("{1}Most scanning operations that use raw sockets, including SYN and UDP {0}"
                          "scans, support this option completely. But this option has no {0}"
                          "effect for any operations that use normal operating system sockets, {0}"
                          "including DNS requests, TCP Connect Scans, version detection, and {0}"
                          "script scanning. Setting the source port also does not work for OS {0}"
                          "detection because nmap must use different port numbers for certain {0}"
                          "OS detection tests to work properly. Since one of your scan options {0}"
                          "is using one of the above operations, it's advised that you not {0}"
                          "continue with this spoofing option. Instead, try running this option{0}"
                          "with a SYN stealth scan and no OS or version detection.".format('\n', red))
                    print()
                    self.select_firewall_spoof_options()
            except AttributeError:
                if self.so1 != '-sT':
                    self.spoof_source_port()
        elif user_input == 4:
            self.select_firewall_spoof_options()
        elif user_input == 5:
            self.select_badsum()
        else:
            self.select_firewall_spoof_options()

    def decoy_cloaking(self):
        """User is displayed decoy cloaking help"""

        print()
        print('A "decoy" scan can make it appear to the target that the host(s) {0}you specify as decoys are scanning '
              'the target too. Thus, their IDS might {0}report 5-10 port scans from unique IP addresses, but '
              'they wont know which IP was {0}scanning them and which were innocent decoys. You can specify a decoy(s) '
              'using {0}the following format: {0}{1}-Ddecoy1.example.com,decoy2example.com {2}or '
              '{1}-D10.0.0.3,10.0.0.6,10.0.0.9'.format('\n', yellow, reset))
        print()
        decoy_input = input('Do you wish to continue with setting decoy(s)? [y/n]. Otherwise, press "{0}b{1}" to '
                            'return {2}back to the other firewall evasion and spoofing options: '
                            .format(yellow, reset, '\n'))
        print()

        if decoy_input.lower() == 'y':
            self.decoy_cloaking_specs()
        elif decoy_input.lower() == 'n':
            self.scan()
        elif decoy_input.lower() == 'b':
            self.select_firewall_spoof_options()
        else:
            print("{0}That's not a valid option".format(red))
            self.decoy_cloaking()

    def decoy_cloaking_specs(self):
        """User selects decoy(s) to use in scan"""

        self.decoy = input('Strictly following the syntax above, enter the {0}decoy(s) {1}you wish to use: '
                           .format(yellow, reset))
        if self.decoy == '':
            print("{0}That's not a valid option. Did you follow the syntax? Or, press 'b' to go back".format(red))
            self.decoy_cloaking_specs()
        elif self.decoy.lower() == 'b':
            self.decoy_cloaking()
        elif not self.decoy.startswith('-D'):  # input validation
            print("{0}That's not a valid option. Did you follow the syntax? Or, press 'b' to go back".format(red))
            self.decoy_cloaking_specs()
        else:
            self.scan_option_selections.append(self.decoy)
            self.verify_additionals()

    def spoof_source_ip(self):  # NEEDS MORE TESTING. APPEARS THIS FEATURE NO LONGER WORKS FOR NMAP
        """User selects a source IP address to spoof"""

        print()
        print('In some circumstances, nmap may not be able to determine your source {0} source address (nmap will tell'
              'you if this is the case). In this {1} situation, use the following format to spoof your {2} IP address,'
              'such as {3}-S 192.168.1.70')  # Finish this later.

    def spoof_source_port(self):
        """User displayed source port spoofing help"""

        print()
        print('nmap offers source port spoofing options. Simply provide a source port {0}number and nmap will send '
              'packets from that port where {1}possible. Use the following syntax, such as: {2}--source-port 53'
              .format('\n', '\n', yellow))
        print()
        port_input = input('Do you wish to continue with spoofing the source port? [y/n]. Otherwise, press "{0}b{1}" '
                           'to return {2}back to the other firewall evasion and spoofing options: '
                           .format(yellow, reset, '\n'))
        print()

        if port_input.lower() == 'y':
            self.spoof_source_port_specs()
        elif port_input.lower() == 'n':
            self.scan()
        elif port_input.lower() == 'b':
            self.select_firewall_spoof_options()
        else:
            print("{0}That's not a valid option.".format(red))
            self.spoof_source_port()

    def spoof_source_port_specs(self):
        """User selects a source port to spoof"""

        self.spoof_port = input('Strictly following the syntax above, enter the {0}port # {1}you wish to use: '
                                .format(yellow, reset))
        if self.spoof_port == '':
            print("{0}That's not a valid option. Did you follow the syntax? Or, press 'b' to go back".format(red))
            self.spoof_source_port_specs()
        elif self.spoof_port.lower() == 'b':
            self.spoof_source_port()
        elif not self.spoof_port.startswith('--source-port'):  # input validation
            print("{0}That's not a valid option. Did you follow the syntax? Or, press 'b' to go back".format(red))
            self.spoof_source_port_specs()
        self.scan_option_selections.append(self.spoof_port)
        self.verify_additionals()

    def spoof_mac(self):  # NEEDS MORE TESTING. APPEARS THIS FEATURE NO LONGER WORKS FOR NMAP
        """User spoofs their MAC address"""

        print('{0}mac address randomization {1}added'.format(yellow, reset))
        self.mac = '--spoof-mac 0'
        self.scan_option_selections.append(self.mac)
        mac_input = input('Include more firewall evasion or spoofing options? [y/n]: ')
        if mac_input.lower() == 'n':
            self.scan()
        elif mac_input.lower() == 'y':
            self.select_firewall_spoof_options()
        else:
            print("{0}That's not an option".format(red))
            self.select_firewall_spoof_options()

    def select_badsum(self):
        """User displayed invalid checksum help and selects, if desired"""

        print()
        print('nmap can use an invalid TCP, UDP, or SCTP checksum for packets sent to target {0}hosts. Since virtually '
              'all host IP stacks properly drop these packets, any responses {0}received are likely coming from a '
              'firewall or IDS that did not bother to verify the {0}checksum'.format('\n'))
        print()
        badsum_input = input('Include an {0}invalid checksum {1}in your scan? [y/n]. Otherwise, press "{2}b{3}" '
                             'to {4}return back to the other firewall evasion and spoofing options: '
                             .format(yellow, reset, yellow, reset, '\n'))
        print()
        if badsum_input.lower() == 'y':
            self.badsum = '--badsum'
            self.scan_option_selections.append(self.badsum)
            self.verify_additionals()
        elif badsum_input.lower() == 'n':
            self.scan()
        elif badsum_input.lower() == 'b':
            self.select_firewall_spoof_options()
        else:
            print("{0}That's not an option".format(red))
            self.select_badsum()

    def verify_additionals(self):
        """called in case user wishes to add more firewall evasion or spoofing options before running scan"""

        user_input = input('Include more firewall evasion or spoofing options? [y/n]: ')
        print()
        if user_input.lower() == 'n':
            self.scan()
        elif user_input.lower() == 'y':
            self.select_firewall_spoof_options()
        else:
            print("{0}That's not an option".format(red))
            self.verify_additionals()

    def scan(self):
        """All user selections are run in an nmap scan"""
        print()
        self.scan_option_selections.insert(len(self.scan_option_selections), self.target)
        print(self.scan_option_selections)
        subprocess.call(self.scan_option_selections)
        exit()

title = "NETENUM"
title_text = title.center(24, '*')
print(Fore.LIGHTYELLOW_EX + title_text)

# Check dependencies
dependencies = Dependencies('/usr/bin/', 'nmap')
dependencies.check_directory()

# Choose a target type and continue to generate a custom scan.
select_target_type = TargetType("target type")
select_target_type.display_target_type()
