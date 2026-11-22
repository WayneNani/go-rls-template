import type { ReactNode } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { errorMessage } from "@/lib/api";
import type { PagedList } from "@/lib/paged-list";
import { cn } from "@/lib/utils";

export interface Column<Row> {
  header: string;
  cell: (row: Row) => ReactNode;
  // On the header and every cell, e.g. "hidden sm:table-cell" to leave a column out on phones.
  className?: string;
}

// A server-paged list from usePagedList: loading skeleton, error, empty state, rows, "Load more".
// The order is the server's (keyset paging); there is no client-side sorting. Copy-owned: change
// it to fit the app. Cells wrap, so a phone shows every column that is not hidden there.
export function DataTable<Row>({
  list,
  columns,
  rowKey,
  label,
  empty,
  actions,
  filterLabel,
}: {
  list: PagedList<Row>;
  columns: Column<Row>[];
  rowKey: (row: Row) => string;
  // Accessible name of the table.
  label: string;
  empty: ReactNode;
  // Per-row controls in a last, unlabelled column (e.g. a rename dialog).
  actions?: (row: Row) => ReactNode;
  // Shows a filter field with this label; the list's RPC must match its `query` field.
  filterLabel?: string;
}) {
  const { rows, result } = list;
  const filter = list.filter.trim();
  return (
    <div className="space-y-4">
      {filterLabel && (
        <Input
          type="search"
          aria-label={filterLabel}
          placeholder={filterLabel}
          value={list.filter}
          onChange={(e) => list.setFilter(e.target.value)}
          className="sm:max-w-xs"
        />
      )}
      {result.isPending ? (
        <div className="space-y-2">
          <span className="sr-only">Loading</span>
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
          <Skeleton className="h-8 w-full" />
        </div>
      ) : result.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{errorMessage(result.error)}</AlertDescription>
        </Alert>
      ) : rows.length === 0 ? (
        filter ? (
          <p className="py-10 text-center text-sm text-muted-foreground">Nothing matches “{filter}”.</p>
        ) : (
          empty
        )
      ) : (
        <Table aria-label={label} aria-busy={result.isFetching}>
          <TableHeader>
            <TableRow>
              {columns.map((c) => (
                <TableHead key={c.header} className={c.className}>
                  {c.header}
                </TableHead>
              ))}
              {actions && (
                <TableHead className="w-10">
                  <span className="sr-only">Actions</span>
                </TableHead>
              )}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={rowKey(row)}>
                {columns.map((c) => (
                  <TableCell key={c.header} className={cn("whitespace-normal break-words", c.className)}>
                    {c.cell(row)}
                  </TableCell>
                ))}
                {actions && <TableCell className="text-right">{actions(row)}</TableCell>}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {result.hasNextPage && !result.isError && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void result.fetchNextPage()}
            disabled={result.isFetchingNextPage}
          >
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
