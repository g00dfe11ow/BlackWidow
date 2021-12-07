import pickle
import graphviz
import html
import random
import string

name_dict = string.ascii_uppercase
g = graphviz.Digraph('G', node_attr={'shape': 'record'})
g.attr(rankdir='LR')

with open("./20211021_v1/attack_lookup_table.pickle", "rb") as f:
    attack_lookup_table = pickle.load(f)

successful_xss = set()

with open('./20211021_v1/my_successful_xss.txt', 'r') as f:
    for line in f.readlines():
        successful_xss.add(line.replace('\n', ''))

injected_set = set()
successful_xss_list = list(successful_xss)
for i in successful_xss_list:

    key = str(i)
    try:
        node_injected = attack_lookup_table[key]['injected']
        node_reflected = list(attack_lookup_table[key]['reflected'])
    except KeyError:
        print(f'KeyError: {key}')
        continue

    s1 = str(node_injected[0])
    s2 = str(node_injected[1])
    s3 = str(node_injected[2])

    if not node_reflected:
        continue
    item = s1 + s2
    if item in injected_set:
        continue
    else:
        injected_set.add(item)

    es1 = html.escape(s1)
    es2 = html.escape(s2)
    es3 = html.escape(s3)

    node_name1 = ''.join(random.sample(name_dict, 5))

    g.node(
        node_name1, f'''<
    <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
    <TR>
        <TD>{es1}</TD>
    </TR>
    <TR>
        <TD>{es2})</TD>
    </TR>
    <TR>
        <TD>{es3}</TD>
    </TR>
    </TABLE>>''')

    for j in node_reflected:

        ss1 = str(j[0])
        ss2 = str(j[1])

        ess1 = html.escape(ss1)
        ess2 = html.escape(ss2)

        node_name2 = ''.join(random.sample(name_dict, 5))
        g.node(
            node_name2, f'''<
        <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
        <TR>
            <TD>{ess1}</TD>
        </TR>
        <TR>
            <TD>{ess2}</TD>
        </TR>
        </TABLE>>''')
        g.edge(node_name1, node_name2)

g.view()
print('Done!')

# 97552537
