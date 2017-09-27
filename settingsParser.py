
from xml.dom import  minidom

def parse(filename: str, root: str, settings_tag: str ) -> dict:
    settings = {}
    doc = minidom.parse(filename)
    setting_elements = doc.getElementsByTagName(root)[0].getElementsByTagName(settings_tag)
    for elm in setting_elements:
        settings.update(elm.attributes.items())
    return settings