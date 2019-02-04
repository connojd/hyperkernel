//
// Bareflank Hyperkernel
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef FILE_H
#define FILE_H

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

namespace bfn
{

class file
{
    using pointer = const char *;
    using size_type = std::size_t;

public:

    file(const std::string &filename) :
        m_path{filename}
    {
        fd = open(m_path.c_str(), O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("failed to open file");
        }

        fstat(fd, &m_statbuf);

        m_addr = mmap(NULL, size(), PROT_READ, MAP_SHARED, fd, 0);
        if (m_addr == MAP_FAILED) {
            throw std::runtime_error("failed to map file");
        }
    }

    ~file()
    {
        munmap(m_addr, size());
        close(fd);
    }

    pointer
    data() const noexcept
    { return static_cast<pointer>(m_addr); }

    size_type
    size() const noexcept
    { return m_statbuf.st_size; }

    const std::string &
    path() const noexcept
    { return m_path; }

private:

    int fd;
    void *m_addr;
    std::string m_path;
    struct stat m_statbuf;
};

}

#endif
