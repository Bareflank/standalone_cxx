//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <array>
#include <iostream>

std::array<const char *, 5> logo = {
    "  ___                __ _           _                 \n",
    " | _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__              \n",
    " | _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /            \n",
    " |___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\         \n",
    "                                                      \n"
};

class test_init
{
public:
    test_init()
    {
        for (const auto &elem : logo) {
            std::cout << elem;
        }
    }
};

class test_exit
{
public:
    ~test_exit()
    { std::cout << '\n'; }
};

test_init s_init;

int main(int argc, char *argv[])
{
    static test_exit s_exit;

    try {
        throw std::runtime_error(
            " Please give us a star on: https://github.com/Bareflank/standalone_cxx"
        );
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
    }

    return 0;
}
