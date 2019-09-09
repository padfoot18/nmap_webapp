from django.shortcuts import render
from django.forms import Form, Select, ChoiceField, CharField, TextInput, IntegerField, NumberInput
from user_input import nmap


class UserInputForm(Form):
    SCAN_TYPE_CHOICES = (
        ('hd', 'Host Discovery'),
        ('tcp', 'TCP Scan'),
        ('udp', 'UDP Scan'),
        ('os', 'Remote OS Detection'),
        ('sd', 'Service detection')
    )
    HOST_TYPE_CHOICES = (
        ('single', 'Single Host'),
        ('multiple', 'Multiple hosts separated by space'),
        ('sub' ,'Subnet')
    )
    scan_type = ChoiceField(widget=Select(attrs={'class': 'form-control'}), choices=SCAN_TYPE_CHOICES)
    host_type = ChoiceField(widget=Select(attrs={'class': 'form-control'}), choices=HOST_TYPE_CHOICES)
    host_name = CharField(widget=TextInput(attrs={'class': 'form-control'}), required=True)


def get_user_input(request):
    return render(request, 'main_form.html', {'form': UserInputForm})


def display_result(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = UserInputForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            # process the data in form.cleaned_data as required
            # ...
            scan_type = form.cleaned_data['scan_type']
            host_type = form.cleaned_data['host_type']
            host_name = form.cleaned_data['host_name']

            if scan_type == 'hd':
                if host_type == 'single':
                    output, command = nmap.host_discovery([host_name])
                elif host_type == 'multiple':
                    output, command = nmap.host_discovery(host_name.strip().split(' '))
                elif host_type == 'sub':
                    output, command = nmap.host_discovery_subnet(host_name)

            elif scan_type == 'tcp':
                if host_type == 'single':
                    output, command = nmap.tcp_port_scanner([host_name])
                elif host_type == 'multiple':
                    output, command = nmap.tcp_port_scanner(host_name.strip().split(' '))
                elif host_type == 'sub':
                    output, command = nmap.tcp_scanner_subnet(host_name)

            elif scan_type == 'udp':
                if host_type == 'single':
                    output, command = nmap.udp_port_scanner([host_name])
                elif host_type == 'multiple':
                    output, command = nmap.udp_port_scanner(host_name.strip().split(' '))
                elif host_type == 'sub':
                    output, command = nmap.udp_port_scanner_subnet(host_name)

            elif scan_type == 'os':
                if host_type == 'single':
                    output, command = nmap.os_detection([host_name])
                elif host_type == 'multiple':
                    output, command = nmap.os_detection(host_name.strip().split(' '))
                elif host_type == 'sub':
                    output, command = nmap.os_detection_subnet(host_name)

            elif scan_type == 'sd':
                if host_type == 'single':
                    output, command = nmap.service_detection([host_name])
                elif host_type == 'multiple':
                    output, command = nmap.service_detection(host_name.strip().split(' '))
                elif host_type == 'sub':
                    output, command = nmap.service_detection_subnet(host_name)

    # noinspection PyUnboundLocalVariable
    return render(request, 'result_display.html', context={'result': zip(output, command)})
