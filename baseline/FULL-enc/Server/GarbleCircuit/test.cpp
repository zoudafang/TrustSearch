
#include <iostream>
#include <typeinfo>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-sh2pc/semihonest.h"
#include "emp-sh2pc/sh_party.h"

using namespace emp;
using namespace std;

Integer default_a()
{
    return Integer(32, 2, 1); // 1 代表 Alice
}
Integer default_b()
{
    return Integer(32, 2, 2); // 1 代表 BOB
}
template <typename Op, typename Op2>
int test_int(int party, int range1 = 1 << 20, int range2 = 1 << 20, int runs = 10, Integer a = default_a(), Integer b = default_b())
{
    // PRG prg(fix_key);
    // if (party == ALICE)
    //     runs--;
    for (int i = 0; i < runs; ++i)
    {
        long long ia = 3, ib = 1;
        // prg.random_data(&ia, 8);
        // prg.random_data(&ib, 8);
        // ia %= range1;
        // ib %= range2;
        // printf("ia: %lld, ib: %lld\n", ia, ib);
        // while (Op()(int(ia), int(ib)) != Op()(ia, ib))
        // {
        //     prg.random_data(&ia, 8);
        //     prg.random_data(&ib, 8);
        //     ia %= range1;
        //     ib %= range2;
        // }

        // Integer a(32, ia, ALICE);
        // Integer b(32, ib, BOB);

        // b = Integer(32, 1, BOB);
        // a = Integer(32, 3, ALICE);
        Integer res = Op2()(a, b);

        // if (res.reveal<int>(PUBLIC) != Op()(ia, ib))
        // {
        //     cout << ia << "\t" << ib << "\t" << Op()(ia, ib) << "\t" << res.reveal<int>(PUBLIC) << endl
        //          << flush;
        // }
        cout << "Iteration: " << i << endl;

        cout << i << " i " << endl;
        cout << ia << "\t" << ib << "\t" << Op()(ia, ib) << "\t" << res.reveal<int>(PUBLIC) << endl
             << flush;
        return res.reveal<int>(PUBLIC);
        // assert(res.reveal<int>(PUBLIC) == Op()(ia, ib));
    }
    cout << typeid(Op2).name() << "\t\t\tDONE" << endl;
}

void scratch_pad()
{
    PRG prg(fix_key);
    for (int i = 0; i < 10; ++i)
    {
        long ia, ib;
        prg.random_data(&ia, 8);
        // caluate hamming dist of ia

        printf("ia: %lld\n", __builtin_popcountll(ia));
        Integer a(64, ia, ALICE);
        cout << "HW " << a.hamming_weight().reveal<int>(PUBLIC) << endl;
        cout << "LZ " << a.leading_zeros().reveal<string>(PUBLIC) << endl;
    }
}