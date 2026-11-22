import { keepPreviousData, useInfiniteQuery, type UseInfiniteQueryResult } from "@tanstack/react-query";
import { useEffect, useState } from "react";

export interface PagedList<Row> {
  rows: Row[];
  result: UseInfiniteQueryResult;
  filter: string;
  setFilter: (filter: string) => void;
}

// One server-paged list (page_size / page_token / next_page_token, see TestListsArePaginated)
// with an optional text filter the server matches (the RPC's `query` field). fetchPage gets
// the page token and the filter, trimmed and debounced; the filter is part of the query key,
// so a new filter starts again at the first page. Invalidate with the key's prefix, e.g.
// ["projects"]. Render it with <DataTable>.
export function usePagedList<Page extends { nextPageToken: string }, Row>(
  key: string[],
  fetchPage: (pageToken: string, query: string) => Promise<Page>,
  rowsOf: (page: Page) => Row[],
  { enabled = true } = {},
): PagedList<Row> {
  const [filter, setFilter] = useState("");
  const query = useDebounced(filter.trim(), 300);
  const result = useInfiniteQuery({
    queryKey: [...key, query],
    queryFn: ({ pageParam }) => fetchPage(pageParam, query),
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    placeholderData: keepPreviousData, // keep the old rows on screen while a new filter loads
    enabled,
  });
  return { rows: result.data?.pages.flatMap(rowsOf) ?? [], result, filter, setFilter };
}

function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}
