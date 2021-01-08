# Azure Log Analytics output backend for sigmac
# John Tuckner (@tuckner)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import sys
import re
import json
import xml.etree.ElementTree as xml


from sigma.config.mapping import (
    SimpleFieldMapping, MultiFieldMapping, ConditionalFieldMapping
)
from sigma.parser.condition import SigmaAggregationParser, ConditionOR

from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from sigma.backends.base import SingleTextQueryBackend

from sigma.parser.modifiers.base import SigmaTypeModifier
from sigma.parser.modifiers.transform import SigmaContainsModifier, SigmaStartswithModifier, SigmaEndswithModifier
from .data import sysmon_schema
from .exceptions import NotSupportedError

class AzureLogAnalyticsBackend(SingleTextQueryBackend):
    """Converts Sigma rule into Azure Log Analytics Queries."""
    identifier = "ala"
    active = True
    options = SingleTextQueryBackend.options + (
        ("sysmon", False, "Generate Sysmon event queries for generic rules", None),
        (
            "use_fields",
            False,
            "Use fields to generate project and aggregation clauses",
            None,
        ),
    )
    config_required = False

    andToken = " and "
    orToken = " or "
    notToken = "not "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = ", "
    valueExpression = "\"%s\""
    nullExpression = "isnull(%s)"
    notNullExpression = "isnotnull(%s)"
    mapExpression = "%s == %s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s in %s"
    typedValueExpression = {
        SigmaRegularExpressionModifier: 'matches regex @"%s"',
        SigmaContainsModifier: "contains \"%s\""
    }

    # _WIN_SECURITY_EVENT_MAP = {
    #     "Image": "NewProcessName",
    #     "ParentImage": "ParentProcessName",
    #     "User": "SubjectUserName",
    # }

    def __init__(self, *args, **kwargs):
        """Initialize field mappings."""
        super().__init__(*args, **kwargs)
        self.category = None
        self.product = None
        self.service = None
        self.table = None
        self.eventid = None
        self._parser = None
        self._fields = None
        self._agg_var = None
        self._has_logsource_event_cond = False
        self._is_keywords_detection = False
        self._is_selection_detection = False
        if not self.sysmon and not self.sigmaconfig.config:
            self._field_map = {}#self._WIN_SECURITY_EVENT_MAP
        else:
            self._field_map = {}

    def cleanValue(self, val):
        val = super().cleanValue(str(val))
        val = re.sub(r'\"', '""', val)
        return val

    def map_sysmon_schema(self, eventid):
        schema_keys = []
        try:
            tree = xml.ElementTree(xml.fromstring(sysmon_schema))
        except:
            raise NotSupportedError("Required Sysmon schema not provided")
        root = tree.getroot()
        for child in root.iter('event'):
            if child.attrib['value'] == str(eventid):
                for d in list(child):
                    schema_keys.append(d.attrib["name"])
        parse_arg = ''
        for schema_key in schema_keys:
            parse_arg += "'Data Name=\"{0}\">' {0} '<' * ".format(schema_key)
        return parse_arg

    def default_value_mapping(self, val):
        try:
            # Check whether the input is a valid regex. If this raises an error we know we can
            # treat it as a normal value. Otherwise, we'll assume it's a regex unless it matches
            # common conditions that shouldn't be regexes.
            re.compile(val)

            # If the value doesn't contain any special characters it shouldn't need to be a regex
            if re.match(r'[^\w\s]', val) is None:
                return self.non_regex_value_mapping(val)

            # `abc*` is a valid regexp but the language spec treats this as `endswith`
            if re.match(r'.*[^\.]\*$', val) is not None:
                return self.non_regex_value_mapping(val)

            # TODO: There are probably more scenarios we need to account for here...

            return f'matches regex @"{self.cleanValue(val)}"'
        except re.error:
            return self.non_regex_value_mapping(val)

    def non_regex_value_mapping(self, val):
        op = '=='
        if val.startswith('*'):
            if val.endswith('*'):
                op = 'contains'
            else:
                op = 'endswith'
        elif val.endswith('*'):
            op = 'startswith'

        val = re.sub(r'(^\*|\*$)', '', val)

        return f'{op} @"{self.cleanValue(val)}"'


    def getTable(self, sigmaparser):
        if self.category == "process_creation" and len(set(sigmaparser.values.keys()) - {"Image", "ParentImage",
                                                                                         "CommandLine"}) == 0:
            self.table = "SecurityEvent | where EventID == 4688 "
            self.eventid = "4688"
        elif self.category == "process_creation":
            self.table = "SysmonEvent"
            self.eventid = "1"
        elif self.service and self.service.lower() == "security":
            self.table = "SecurityEvent"
        elif self.service and self.service.lower() == "sysmon":
            self.table = "SysmonEvent"
        elif self.service and self.service.lower().startswith("powershell"):
            self.table = "Event"
        elif self.service and self.service.lower() == "office365":
            self.table = "OfficeActivity"
        elif self.service and self.service.lower() == "azuread":
            self.table = "AuditLogs"
        elif self.service and self.service.lower() == "azureactivity":
            self.table = "AzureActivity"
        else:
            if self.service:
                if "-" in self.service:
                    self.table = "-".join([item.capitalize() for item in self.service.split("-")])
                elif "_" in self.service:
                    self.table = "_".join([item.capitalize() for item in self.service.split("_")])
                else:
                    if self.service.islower() or self.service.isupper():
                        self.table = self.service.capitalize()
                    else:
                        self.table = self.service
            elif self.product:
                if "-" in self.product:
                    self.table = "-".join([item.capitalize() for item in self.product.split("-")])
                elif "_" in self.product:
                    self.table = "_".join([item.capitalize() for item in self.product.split("_")])
                else:
                    if self.product.islower() or self.product.isupper():
                        self.table = self.product.capitalize()
                    else:
                        self.table = self.product
            elif self.category:
                if "-" in self.category:
                    self.table = "-".join([item.capitalize() for item in self.category.split("-")])
                elif "_" in self.category:
                    self.table = "_".join([item.capitalize() for item in self.category.split("_")])
                else:
                    if self.category.islower() or self.category.isupper():
                        self.table = self.category.capitalize()
                    else:
                        self.table = self.category

    def generate(self, sigmaparser):
        try:
            self.category = sigmaparser.parsedyaml['logsource'].setdefault('category', None)
            self.product = sigmaparser.parsedyaml['logsource'].setdefault('product', None)
            self.service = sigmaparser.parsedyaml['logsource'].setdefault('service', None)
        except KeyError:
            self.category = None
            self.product = None
            self.service = None

        detection = sigmaparser.parsedyaml.get("detection", {})

        if self.table is None:
            self.getTable(sigmaparser)

        if 'keywords' in detection.keys() or 'keyword' in detection.keys():
            self._is_keywords_detection = True

        if len([ k for k in detection.keys() if k.startswith('selection')]) > 0:
            self._is_selection_detection = True

        return super().generate(sigmaparser)

    def generateBefore(self, parsed):
        if self.table is None:
            raise NotSupportedError("No table could be determined from Sigma rule")
        if self.category == "process_creation" and self.sysmon:
            parse_string = self.map_sysmon_schema(self.eventid)
            before = "%s | parse EventData with * %s | where EventID == \"%s\" | where " % (self.table, parse_string, self.eventid)
        elif self.sysmon:
            parse_string = self.map_sysmon_schema(self.eventid)
            before = "%s | parse EventData with * %s | where " % (self.table, parse_string)
        # elif self.category == "process_creation" and not self._has_logsource_event_cond:
        #     before = "%s | where EventID == \"%s\" | where " % (self.table, self.eventid)
        else:
            before = "%s | where " % self.table
        return before

    def generateMapItemNode(self, node):
        """
        ALA queries, like ATP, refer to event tables instead of Windows logging event identifiers. This method catches conditions that refer to this field
        and creates an appropriate table reference.
        """
        key, value = node
        key = self.fieldNameMapping(key, value)
        if type(value) == list:         # handle map items with values list like multiple OR-chained conditions
            return "(" + self.generateORNode(
                    [(key, v) for v in value]
                    ) + ")"
        elif key.lower() in ['eventid', 'event_id']:            # EventIDs are not reflected in condition but in table selection
            if self.service == "sysmon":
                self.table = "SysmonEvent"
                self.eventid = str(value)
            elif self.service == "powershell":
                self.table = "Event"
            elif self.service == "security":
                self.table = "SecurityEvent"
            elif self.service == "system":
                self.table = "Event"
            return self.mapExpression % (key, value)
        elif type(value) in [SigmaTypeModifier, SigmaContainsModifier, SigmaRegularExpressionModifier, SigmaStartswithModifier, SigmaEndswithModifier]:
            return self.generateMapItemTypedNode(key, value)
        elif type(value) in (str, int):    # default value processing'
            #default_filters = ["endswith", "contains", "startswith", "re"]
            # if any([item for item in default_filters if item in key]):
            #     key = re.sub(key, default_filters, "")
            #     return self.regexExpression % (key, self.cleanValue(value))
            # else:
            #     value_mapping = self.default_value_mapping
            value_mapping = self.default_value_mapping
            mapping = (key, value_mapping)
            if len(mapping) == 1:
                mapping = mapping[0]
                if type(mapping) == str:
                    return mapping
                elif callable(mapping):
                    return self.generateSubexpressionNode(
                            self.generateANDNode(
                                [cond for cond in mapping(key, self.cleanValue(value))]
                                )
                            )
            elif len(mapping) == 2:
                result = list()
                for mapitem, val in zip(mapping, node):     # iterate mapping and mapping source value synchronously over key and value
                    if type(mapitem) == str:
                        result.append(mapitem)
                    elif callable(mapitem):
                        result.append(mapitem(self.cleanValue(val)))
                return "{} {}".format(*result)
            else:
                raise TypeError("Backend does not support map values of type " + str(type(value)))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)

        elif value is None:
            return self.nullExpression % (key, )
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemTypedNode(self, fieldname, value):
        return "%s %s" % (fieldname, self.generateTypedValueNode(value))

    def generateTypedValueNode(self, node):
        try:
            val = str(node)
            return self.typedValueExpression[type(node)] % (val)
        except KeyError:
            raise NotImplementedError("Type modifier '{}' is not supported by backend".format(node.identifier))

    def generateAggregation(self, agg):
        if agg is None:
            return ""
        if agg.aggfunc == SigmaAggregationParser.AGGFUNC_NEAR:
            raise NotImplementedError(
                "The 'near' aggregation operator is not "
                + f"implemented for the %s backend" % self.identifier
            )
        if agg.aggfunc_notrans != 'count' and agg.aggfield is None:
            raise NotSupportedError(
                "The '%s' aggregation operator " % agg.aggfunc_notrans
                + "must have an aggregation field for the %s backend" % self.identifier
            )
        if agg.aggfunc_notrans == 'count' and agg.aggfield is not None:
            agg_func = "dcount"
        else:
            agg_func = agg.aggfunc_notrans

        self._agg_var = agg_func + ("_" + agg.aggfield) if agg.aggfield else "var"
        if not self._fields:
            by_clause = "by {grp}".format(grp=agg.groupfield if agg.groupfield else "")
        else:
            if agg.aggfield_notrans in self._fields:
                self._fields.remove(agg.aggfield_notrans)
            by_clause = "by {grp}".format(grp=", ".join(self._map_fields(self._fields)))
        return (
            " | summarize {var} = {func}({fld}) {by} | where {var} {op} {cond}".format(
                var=self._agg_var,
                func=agg_func,
                fld=agg.aggfield or "",
                by=by_clause,
                op=agg.cond_op,
                cond=agg.condition,
            )
        )

    def generate_keyword_expression(self, val):
        val = self.default_value_mapping(val)

        # Check if the keyword expression has a wildcard in the interior of the string.
        # In this case, the KQL will need to use regex and the rest of the string needs to be escaped.
        if '*' in val[1:-1]:
            val = re.sub(r'(==|contains)', 'matches regex', val)
            val = re.sub(r'([\\\^\$\.\|\?\(\)\[\{])', r'\\\1', val)
            val = re.sub(r'\*', '.*', val)

        # Most rules that don't explicitly specify wildcards that would have been caught by the
        # previous run through `self.default_value_mapping` assume a string wrapped in wildcards
        val = re.sub(r'==', 'contains', val)

        return f'* {val}'

    def generateNode(self, node):
        if self._is_keywords_detection == True or self._is_selection_detection == True:
            if type(node) == str:
                return self.generate_keyword_expression(node)

        return super().generateNode(node)

    def _map_conditional_field(self, fieldname):
        mapping = self.sigmaconfig.fieldmappings.get(fieldname)
        # if there is a conditional mapping for this fieldname
        # and it matches the current event id, get the mapping
        if (
            mapping
            and isinstance(mapping, ConditionalFieldMapping)
            and "EventID" in mapping.conditions
        ):
            fieldname = mapping.conditions["EventID"].get(self.eventid, [fieldname])[0]
        elif self._field_map:
            # Fall back to default internal map if no config
            return self._field_map.get(fieldname, fieldname)
        return fieldname

class AzureAPIBackend(AzureLogAnalyticsBackend):
    """Converts Sigma rule into Azure Log Analytics Rule."""
    identifier = "ala-rule"
    active = True
    options = SingleTextQueryBackend.options + (
            ("sysmon", False, "Generate Sysmon event queries for generic rules", None),
            )

    def __init__(self, *args, **kwargs):
        """Initialize field mappings"""
        super().__init__(*args, **kwargs)
        self.techniques = self._load_mitre_file("techniques")

    def find_technique(self, key_ids):
        for key_id in set(key_ids):
            if not key_id:
                continue
            for technique in self.techniques:
                if key_id == technique.get("technique_id", ""):
                    yield technique

    def _load_mitre_file(self, mitre_type):
        try:
            backend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config", "mitre"))
            path = os.path.join(backend_dir, "{}.json".format(mitre_type))
            with open(path) as config_file:
                config = json.load(config_file)
                return config
        except (IOError, OSError) as e:
            print("Failed to open {} configuration file '%s': %s".format(path, str(e)), file=sys.stderr)
            return []
        except json.JSONDecodeError as e:
            print("Failed to parse {} configuration file '%s' as valid YAML: %s" % (path, str(e)), file=sys.stderr)
            return []

    def skip_tactics_or_techniques(self, src_technics, src_tactics):
        tactics = set()
        technics = set()

        local_storage_techniques = {item["technique_id"]: item for item in self.find_technique(src_technics)}

        for key_id in src_technics:
            src_tactic = local_storage_techniques.get(key_id, {}).get("tactic")
            if not src_tactic:
                continue
            src_tactic = set(src_tactic)

            for item in src_tactics:
                if item in src_tactic:
                    technics.add(key_id)
                    tactics.add(item)

        return sorted(tactics), sorted(technics)

    def parse_severity(self, old_severity):
        if old_severity.lower() == "critical":
            return "high"
        return old_severity

    def get_tactics_and_techniques(self, tags):
        tactics = list()
        technics = list()

        for tag in tags:
            tag = tag.replace("attack.", "")
            if re.match("[t][0-9]{4}", tag, re.IGNORECASE):
                technics.append(tag.title())
            else:
                if "_" in tag:
                    tag = tag.replace("_", " ")
                tag = tag.title()
                tactics.append(tag)

        return tactics, technics

    def create_rule(self, config):
        tags = config.get("tags", [])

        tactics, technics = self.get_tactics_and_techniques(tags)
        tactics, technics = self.skip_tactics_or_techniques(technics, tactics)
        tactics = list(map(lambda s: s.replace(" ", ""), tactics))

        rule = {
                "displayName": "{} by {}".format(config.get("title"), config.get('author')),
                "description": "{} {}".format(config.get("description"), "Technique: {}.".format(",".join(technics))),
                "severity": self.parse_severity(config.get("level", "medium")),
                "enabled": True,
                "query": config.get("translation"),
                "queryFrequency": "12H",
                "queryPeriod": "12H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "suppressionDuration": "12H",
                "suppressionEnabled": True,
                "tactics": tactics
            }
        return json.dumps(rule)

    def generate(self, sigmaparser):
        translation = super().generate(sigmaparser)
        if translation:
            configs = sigmaparser.parsedyaml
            configs.update({"translation": translation})
            rule = self.create_rule(configs)
            return rule
        else:
            raise NotSupportedError("No table could be determined from Sigma rule")
