/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEM_POOL_H_
#define BOTAN_MEM_POOL_H_

#include <botan/types.h>
#include <botan/mutex.h>
#include <vector>
#include <deque>
#include <map>

namespace Botan {

class Bucket;

class BOTAN_TEST_API Memory_Pool final
   {
   public:
      /**
      * Initialize a memory pool. The memory is not owned by *this,
      * it must be freed by the caller.
      * @param pages a set of equal-sized regions of memory
      * @param page_size the size of each page (does not need to match
      *        the system page size)
      */
      Memory_Pool(const std::vector<void*>& pages,
                  size_t page_size);

      ~Memory_Pool();

      void* allocate(size_t size);

      bool deallocate(void* p, size_t size) noexcept;

      Memory_Pool(const Memory_Pool&) = delete;
      Memory_Pool(Memory_Pool&&) = delete;

      Memory_Pool& operator=(const Memory_Pool&) = delete;
      Memory_Pool& operator=(Memory_Pool&&) = delete;

   private:
      const size_t m_page_size = 0;

      mutex_type m_mutex;

      std::deque<uint8_t*> m_free_pages;
      std::map<size_t, std::deque<Bucket>> m_buckets_for;
   };

}

#endif
