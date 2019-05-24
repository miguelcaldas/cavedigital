# Azure template for SharePoint 2019 / 2016 / 2013

This template deploys SharePoint 2016

<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmiguelcaldas%2Fcavedigital%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>
<a href="http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fmiguelcaldas%2Fcavedigital%2Fmaster%2Fazuredeploy.json" target="_blank">
    <img src="http://armviz.io/visualizebutton.png"/>
</a>

By default, virtual machines running SharePoint and SQL use SSD drives and have enough CPU and memory to be used comfortably for development and tests:

* Virtual machine running the Domain Controller: [Standard_F4](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes-compute#fsv2-series-sup1sup) / Standard_LRS
* Virtual machine running SQL Server: [Standard_DS2_v2](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes-general#dsv2-series) / Standard_LRS
* Virtual machine(s) running SharePoint: [Standard_DS3_v2](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/sizes-general#dsv2-series) / Standard_LRS

> **Notes:**  
Be careful with passwords!!!
