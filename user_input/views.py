from django.shortcuts import render
from django.forms import Form, Select, ChoiceField, CharField, TextInput, IntegerField, NumberInput
from django.http import HttpResponseRedirect


class UserInputForm(Form):
    SCAN_TYPE_CHOICES = (
        ('hd', 'Host Discovery'),
        ('ps', 'Port Scan'),
        ('tcp', 'TCP Scan'),
        ('udp', 'UDP Scan'),
        ('os', 'Remote OS Detection'),
        ('sd', 'Service detection')
    )
    HOST_TYPE_CHOICES = (
        ('single', 'Single Host'),
        ('range', 'Range of hosts'),
        ('sub' ,'Subnet')
    )
    scan_type = ChoiceField(widget=Select(attrs={'class': 'form-control'}), choices=SCAN_TYPE_CHOICES)
    host_type = ChoiceField(widget=Select(attrs={'class': 'form-control'}), choices=HOST_TYPE_CHOICES)
    host_name = CharField(widget=TextInput(attrs={'class': 'form-control'}), required=True)
    port = IntegerField(widget=NumberInput(attrs={'class': 'form-control', 'min': '1', 'max': '65535'}), required=False)


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
            port = form.cleaned_data['port']

    # noinspection PyUnboundLocalVariable
    return render(request, 'result_display.html', context={'data': [scan_type, host_name, host_type, port]})
