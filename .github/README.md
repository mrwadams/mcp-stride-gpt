# GitHub Actions Workflows

This directory contains CI/CD workflow definitions for automated testing.

## Note on Workflow Permissions

The GitHub Actions workflow file (`test.yml`) was created but could not be automatically committed due to GitHub App permissions restrictions. GitHub Apps require the `workflows` permission to create or modify workflow files.

## Manual Setup Instructions

If you want to enable automated testing with GitHub Actions:

1. **Option 1 - Manual Commit**:
   - Copy the `test.yml` file content from the local `.github/workflows/` directory
   - Create the file manually through GitHub's web interface
   - Or commit it locally with git permissions

2. **Option 2 - Use this Repository Structure**:
   The workflow file has been created locally at:
   ```
   .github/workflows/test.yml
   ```

   You can commit it manually with:
   ```bash
   git add .github/workflows/test.yml
   git commit -m "Add GitHub Actions CI/CD workflow"
   git push
   ```

## Workflow Features

The CI/CD pipeline includes:
- ✅ Automated testing on Python 3.9, 3.10, 3.11, 3.12
- ✅ Coverage reporting with Codecov integration
- ✅ Code linting with ruff
- ✅ Runs on pushes to main/develop branches
- ✅ Runs on all pull requests

## Alternative: No CI/CD Required

If you prefer not to use GitHub Actions:
- Tests can be run locally with `pytest`
- The test suite works perfectly without CI/CD
- Just ensure tests pass before deploying to Vercel
