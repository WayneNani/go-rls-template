-- Rows the browser tests create (make e2e-clean, after every make e2e). make scaffold adds its tables.
delete from app.projects where name like 'E2E %';
