import unittest
import tempfile
import os
import yaml
import types

from hier_config import HConfig
from hier_config.host import Host


class TestHConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.os = 'ios'
        cls.options_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'files',
            'test_options_ios.yml',
        )
        cls.tags_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'files',
            'test_tags_ios.yml',
        )
        cls.running_cfg = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'files',
            'running_config.conf',
        )
        cls.compiled_cfg = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'files',
            'compiled_config.conf',
        )

        with open(cls.tags_file) as f:
            cls.tags = yaml.safe_load(f.read())

        with open(cls.options_file) as f:
            cls.options = yaml.safe_load(f.read())

        cls.host_a = Host('example1.rtr', cls.os, cls.options)
        cls.host_b = Host('example2.rtr', cls.os, cls.options)

    def test_bool(self):
        self.assertTrue(HConfig(host=self.host_a))

    def test_merge(self):
        hier1 = HConfig(host=self.host_a)
        hier1.add_child('interface Vlan2')
        hier2 = HConfig(host=self.host_b)
        hier2.add_child('interface Vlan3')

        self.assertEqual(1, len(list(hier1.all_children())))
        self.assertEqual(1, len(list(hier2.all_children())))

        hier1.merge(hier2)

        self.assertEqual(2, len(list(hier1.all_children())))

    def test_load_from_file(self):
        hier = HConfig(host=self.host_a)
        config = 'interface Vlan2\n ip address 1.1.1.1 255.255.255.0'

        with tempfile.NamedTemporaryFile(mode='r+') as myfile:
            myfile.file.write(config)
            myfile.file.flush()
            hier.load_from_file(myfile.name)

        self.assertEqual(2, len(list(hier.all_children())))

    def test_load_from_config_text(self):
        hier = HConfig(host=self.host_a)
        config = 'interface Vlan2\n ip address 1.1.1.1 255.255.255.0'

        hier.load_from_string(config)
        self.assertEqual(2, len(list(hier.all_children())))

    def test_dump_and_load_from_dump_and_compare(self):
        hier_pre_dump = HConfig(host=self.host_a)
        a1 = hier_pre_dump.add_child('a1')
        b2 = a1.add_child('b2')

        b2.order_weight = 400
        b2.tags.add('test')
        b2.comments.add('test comment')
        b2.new_in_config = True

        dump = hier_pre_dump.dump()

        hier_post_dump = HConfig(host=self.host_a)
        hier_post_dump.load_from_dump(dump)

        self.assertEqual(hier_pre_dump, hier_post_dump)

    def test_add_tags(self):
        hier = HConfig(host=self.host_a)
        tag_rules = [{
            'lineage': [{'equals': 'interface Vlan2'}],
            'add_tags': 'test'}]
        child = hier.add_child('interface Vlan2')

        hier.add_tags(tag_rules)

        self.assertEqual({'test'}, child.tags)

    def test_all_children_sorted_by_lineage_rules(self):
        hier = HConfig(host=self.host_a)
        svi = hier.add_child('interface Vlan2')
        svi.add_child('description switch-mgmt-10.0.2.0/24')

        mgmt = hier.add_child('interface FastEthernet0')
        mgmt.add_child('description mgmt-192.168.0.0/24')

        self.assertEqual(4, len(list(hier.all_children())))
        self.assertTrue(isinstance(hier.all_children(), types.GeneratorType))

        self.assertEqual(
            2, len(list(hier.all_children_sorted_with_lineage_rules(self.tags))))
        self.assertTrue(isinstance(
            hier.all_children_sorted_with_lineage_rules(self.tags), types.GeneratorType))

    def test_add_ancestor_copy_of(self):
        hier1 = HConfig(host=self.host_a)
        interface = hier1.add_child('interface Vlan2')
        interface.add_children(['description switch-mgmt-192.168.1.0/24', 'ip address 192.168.1.0/24'])
        hier1.add_ancestor_copy_of(interface)

        self.assertEqual(3, len(list(hier1.all_children())))
        self.assertTrue(isinstance(hier1.all_children(), types.GeneratorType))

    def test_has_children(self):
        hier = HConfig(host=self.host_a)
        self.assertFalse(hier.has_children())
        hier.add_child('interface Vlan2')
        self.assertTrue(hier.has_children())

    def test_depth(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        ip_address = interface.add_child(
            'ip address 192.168.1.1 255.255.255.0')
        self.assertEqual(2, ip_address.depth())

    def test_get_child(self):
        hier = HConfig(host=self.host_a)
        hier.add_child('interface Vlan2')
        child = hier.get_child('equals', 'interface Vlan2')
        self.assertEqual('interface Vlan2', child.text)

    def test_get_child_deep(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        interface.add_child('ip address 192.168.1.1 255.255.255.0')
        child = hier.get_child_deep([
            ('equals', 'interface Vlan2'),
            ('equals', 'ip address 192.168.1.1 255.255.255.0')])
        self.assertIsNotNone(child)

    def test_get_children(self):
        hier = HConfig(host=self.host_a)
        hier.add_child('interface Vlan2')
        hier.add_child('interface Vlan3')
        children = hier.get_children('startswith', 'interface')
        self.assertEqual(2, len(list(children)))

    def test_move(self):
        hier1 = HConfig(host=self.host_a)
        interface1 = hier1.add_child('interface Vlan2')
        interface1.add_child('192.168.0.1/30')

        self.assertEqual(2, len(list(hier1.all_children())))

        hier2 = HConfig(host=self.host_b)

        self.assertEqual(0, len(list(hier2.all_children())))

        interface1.move(hier2)

        self.assertEqual(0, len(list(hier1.all_children())))
        self.assertEqual(2, len(list(hier2.all_children())))

    def test_del_child_by_text(self):
        hier = HConfig(host=self.host_a)
        hier.add_child('interface Vlan2')
        hier.del_child_by_text('interface Vlan2')

        self.assertEqual(0, len(list(hier.all_children())))

    def test_del_child(self):
        hier1 = HConfig(host=self.host_a)
        hier1.add_child('interface Vlan2')

        self.assertEqual(1, len(list(hier1.all_children())))

        hier1.del_child(hier1.get_child('startswith', 'interface'))

        self.assertEqual(0, len(list(hier1.all_children())))

    def test_rebuild_children_dict(self):
        hier1 = HConfig(host=self.host_a)
        interface = hier1.add_child('interface Vlan2')
        interface.add_children(['description switch-mgmt-192.168.1.0/24', 'ip address 192.168.1.0/24'])
        delta_a = hier1
        hier1.rebuild_children_dict()
        delta_b = hier1

        self.assertEqual(list(delta_a.all_children()), list(delta_b.all_children()))

    def test_add_children(self):
        interface_items1 = ['description switch-mgmt 192.168.1.0/24', 'ip address 192.168.1.1/24']
        hier1 = HConfig(host=self.host_a)
        interface1 = hier1.add_child('interface Vlan2')
        interface1.add_children(interface_items1)

        self.assertEqual(3, len(list(hier1.all_children())))

        interface_items2 = "description switch-mgmt 192.168.1.0/24"
        hier2 = HConfig(host=self.host_a)
        interface2 = hier2.add_child('interface Vlan2')
        interface2.add_children(interface_items2)

        self.assertEqual(2, len(list(hier2.all_children())))

    def test_add_child(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        self.assertEqual(1, interface.depth())
        self.assertEqual('interface Vlan2', interface.text)
        self.assertFalse(isinstance(interface, list))

    def test_add_deep_copy_of(self):
        hier1 = HConfig(host=self.host_a)
        interface1 = hier1.add_child('interface Vlan2')
        interface1.add_children(['description switch-mgmt-192.168.1.0/24', 'ip address 192.168.1.0/24'])

        hier2 = HConfig(host=self.host_b)
        hier2.add_deep_copy_of(interface1)

        self.assertEqual(3, len(list(hier2.all_children())))
        self.assertTrue(isinstance(hier2.all_children(), types.GeneratorType))

    def test_lineage(self):
        pass

    def test_path(self):
        pass

    def test_cisco_style_text(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        ip_address = interface.add_child(
            'ip address 192.168.1.1 255.255.255.0')
        self.assertEqual(
            '  ip address 192.168.1.1 255.255.255.0',
            ip_address.cisco_style_text())
        self.assertNotEqual(
            ' ip address 192.168.1.1 255.255.255.0',
            ip_address.cisco_style_text())
        self.assertTrue(isinstance(ip_address.cisco_style_text(), str))
        self.assertFalse(isinstance(ip_address.cisco_style_text(), list))

    def test_all_children_sorted_untagged(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address_a = interface.add_child('ip address 192.168.1.1/24')
        ip_address_a.append_tags('a')
        ip_address_none = interface.add_child('ip address 192.168.2.1/24')

        self.assertIs(ip_address_none, list(config.all_children_sorted_untagged())[1])
        self.assertEqual(2, len(list(config.all_children_sorted_untagged())))
        self.assertIs(ip_address_none, list(config.all_children_sorted_untagged())[1])

    def test_all_children_sorted_by_tags(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address_a = interface.add_child('ip address 192.168.1.1/24')
        ip_address_a.append_tags('a')
        ip_address_ab = interface.add_child('ip address 192.168.2.1/24')
        ip_address_ab.append_tags(['a', 'b'])

        self.assertEqual(2, len(list(config.all_children_sorted_by_tags('a', 'b'))))
        self.assertIs(ip_address_a, list(config.all_children_sorted_by_tags('a', 'b'))[1])
        self.assertEqual(3, len(list(config.all_children_sorted_by_tags('a', ''))))
        self.assertEqual(0, len(list(config.all_children_sorted_by_tags('', 'a'))))
        self.assertEqual(3, len(list(config.all_children_sorted_by_tags('', ''))))

        """
        interface Vlan2 ! a,b
          ip address 192.168.1.1/24 ! a
          ip address 192.168.2.1/24 ! a,b
        """

    def test_all_children_sorted(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        interface.add_child('standby 1 ip 10.15.11.1')
        self.assertEqual(2, len(list(hier.all_children_sorted())))

    def test_all_children(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        interface.add_child('standby 1 ip 10.15.11.1')
        self.assertEqual(2, len(list(hier.all_children())))

    def test_delete(self):
        pass

    def test_set_order_weight(self):
        hier = HConfig(host=self.host_a)
        child = hier.add_child('no vlan filter')
        hier.set_order_weight()
        self.assertEqual(child.order_weight, 700)

    def test_add_sectional_exiting(self):
        hier = HConfig(host=self.host_a)
        bgp = hier.add_child('router bgp 64500')
        template = bgp.add_child('template peer-policy')
        hier.add_sectional_exiting()
        sectional_exit = template.get_child('equals', 'exit-peer-policy')
        self.assertIsNotNone(sectional_exit)

    def test_to_tag_spec(self):
        pass

    def test_tags(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address = interface.add_child('ip address 192.168.1.1/24')
        self.assertTrue(None in interface.tags)
        self.assertTrue(None in ip_address.tags)
        ip_address.append_tags('a')
        self.assertTrue('a' in interface.tags)
        self.assertTrue('a' in ip_address.tags)
        self.assertFalse('b' in interface.tags)
        self.assertFalse('b' in ip_address.tags)

    def test_append_tags(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address = interface.add_child('ip address 192.168.1.1/24')
        ip_address.append_tags('test_tag')
        self.assertIn('test_tag', config.tags)
        self.assertIn('test_tag', interface.tags)
        self.assertIn('test_tag', ip_address.tags)

    def test_remove_tags(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address = interface.add_child('ip address 192.168.1.1/24')
        ip_address.append_tags('test_tag')
        self.assertIn('test_tag', config.tags)
        self.assertIn('test_tag', interface.tags)
        self.assertIn('test_tag', ip_address.tags)
        ip_address.remove_tags('test_tag')
        self.assertNotIn('test_tag', config.tags)
        self.assertNotIn('test_tag', interface.tags)
        self.assertNotIn('test_tag', ip_address.tags)

    def test_with_tags(self):
        pass

    def test_negate(self):
        hier = HConfig(host=self.host_a)
        interface = hier.add_child('interface Vlan2')
        interface.negate()
        self.assertEqual('no interface Vlan2', interface.text)

    def test_config_to_get_to(self):
        running_config_hier = HConfig(host=self.host_a)
        interface = running_config_hier.add_child('interface Vlan2')
        interface.add_child('ip address 192.168.1.1/24')
        compiled_config_hier = HConfig(host=self.host_a)
        compiled_config_hier.add_child('interface Vlan3')
        remediation_config_hier = running_config_hier.config_to_get_to(compiled_config_hier)
        self.assertEqual(2, len(list(remediation_config_hier.all_children())))

    def test_config_to_get_to_right(self):
        running_config_hier = HConfig(host=self.host_a)
        running_config_hier.add_child('do not add me')
        compiled_config_hier = HConfig(host=self.host_a)
        compiled_config_hier.add_child('do not add me')
        compiled_config_hier.add_child('add me')
        delta = HConfig(host=self.host_a)
        running_config_hier._config_to_get_to_right(compiled_config_hier, delta)
        self.assertNotIn('do not add me', delta)
        self.assertIn('add me', delta)

    def test_is_idempotent_command(self):
        pass

    def test_sectional_overwrite_no_negate_check(self):
        pass

    def test_sectional_overwrite_check(self):
        pass

    def test_overwrite_with(self):
        pass

    def test_add_shallow_copy_of(self):
        pass

    def test_line_inclusion_test(self):
        config = HConfig(host=self.host_a)
        interface = config.add_child('interface Vlan2')
        ip_address = interface.add_child('ip address 192.168.1.1/24')
        ip_address_a = interface.add_child('ip address 192.168.2.1/24')
        ip_address_a.append_tags('a')
        ip_address_ab = interface.add_child('ip address 192.168.3.1/24')
        ip_address_ab.append_tags(['a', 'b'])

        self.assertTrue(ip_address.line_inclusion_test('', ''))
        self.assertTrue(ip_address.line_inclusion_test(None, ''))
        self.assertFalse(ip_address.line_inclusion_test('', None))

        self.assertFalse(ip_address_a.line_inclusion_test('', 'a'))
        self.assertTrue(ip_address_a.line_inclusion_test('a', ''))
        self.assertTrue(ip_address_a.line_inclusion_test('', ''))
        self.assertFalse(ip_address_a.line_inclusion_test(None, ''))
        self.assertTrue(ip_address_a.line_inclusion_test('', None))

        self.assertFalse(ip_address_ab.line_inclusion_test('a', 'b'))
        self.assertFalse(ip_address_ab.line_inclusion_test('', 'a'))
        self.assertTrue(ip_address_ab.line_inclusion_test('a', ''))
        self.assertTrue(ip_address_ab.line_inclusion_test('', ''))
        self.assertFalse(ip_address_ab.line_inclusion_test(None, ''))
        self.assertTrue(ip_address_ab.line_inclusion_test('', None))

    def test_lineage_test(self):
        pass

    def test_difference(self):
        rc = ['a', ' a1', ' a2', ' a3', 'b']
        step = ['a', ' a1', ' a2', ' a3', ' a4', ' a5', 'b', 'c', 'd', ' d1']
        rc_hier = HConfig(host=self.host_a)
        rc_hier.load_from_string("\n".join(rc))
        step_hier = HConfig(host=self.host_a)
        step_hier.load_from_string("\n".join(step))

        difference = step_hier.difference(rc_hier)
        difference_children = list(c.cisco_style_text() for c in difference.all_children_sorted())
        self.assertEqual(len(difference_children), 6)
        self.assertIn('c', difference)
        self.assertIn('d', difference)
        self.assertIn('a4', difference.get_child('equals', 'a'))
        self.assertIn('a5', difference.get_child('equals', 'a'))
        self.assertIn('d1', difference.get_child('equals', 'd'))


if __name__ == "__main__":
    unittest.main(failfast=True)
