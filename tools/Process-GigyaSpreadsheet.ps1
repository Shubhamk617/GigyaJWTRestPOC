param(
    [string]$Path = "$PSScriptRoot\..\App_Data\Gigya_Migration_Detailed.xlsx"
)

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    exit 1
}

# Uses Excel COM automation. Excel must be installed on the machine running this script.
$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$workbook = $excel.Workbooks.Open((Resolve-Path $Path).ProviderPath)
try {
    $sheet = $workbook.Worksheets.Item(1)
    $used = $sheet.UsedRange
    $firstRow = $used.Row
    $firstCol = $used.Column
    $lastRow = $used.Rows.Count + $firstRow - 1
    $lastCol = $used.Columns.Count + $firstCol - 1

    # Find header indexes for the two columns to combine
    $headerMap = @{}
    for ($c = $firstCol; $c -le $lastCol; $c++) {
        $h = ($sheet.Cells.Item($firstRow, $c).Text -as [string]).Trim()
        if (-not [string]::IsNullOrWhiteSpace($h)) { $headerMap[$h] = $c }
    }

    $colAName = 'Recommended Setup'
    $colBName = 'Recommendation / Action'
    if (-not $headerMap.ContainsKey($colAName) -or -not $headerMap.ContainsKey($colBName)) {
        Write-Warning "One or both headers not found. Available headers: $($headerMap.Keys -join ', ')"
    } else {
        $colA = $headerMap[$colAName]
        $colB = $headerMap[$colBName]

        # Create a new header name for the merged column and write it into colA
        $mergedHeader = "$colAName / $colBName"
        $sheet.Cells.Item($firstRow, $colA).Value2 = $mergedHeader

        # Merge content row by row into colA
        for ($r = $firstRow + 1; $r -le $lastRow; $r++) {
            $a = ($sheet.Cells.Item($r, $colA).Text -as [string]).Trim()
            $b = ($sheet.Cells.Item($r, $colB).Text -as [string]).Trim()
            if ([string]::IsNullOrWhiteSpace($a)) { $combined = $b } 
            elseif ([string]::IsNullOrWhiteSpace($b)) { $combined = $a } 
            else { $combined = "$a`n$b" }
            $sheet.Cells.Item($r, $colA).Value2 = $combined
        }

        # Delete the second column (colB).
        $sheet.Columns.Item($colB).Delete()
        # refresh used range
        $used = $sheet.UsedRange; $firstRow = $used.Row; $firstCol = $used.Column; $lastRow = $used.Rows.Count + $firstRow - 1; $lastCol = $used.Columns.Count + $firstCol - 1
    }

    # Move special rows into a new sheet named 'Observations'
    $observationTitles = @('Approach 2 Benefits','Approach 2 Drawbacks','Logging & Debugging')
    # create (or clear) Observations sheet
    $obsSheet = $null
    foreach ($s in $workbook.Worksheets) { if ($s.Name -eq 'Observations') { $obsSheet = $s; break } }
    if ($obsSheet -eq $null) { $obsSheet = $workbook.Worksheets.Add(); $obsSheet.Name = 'Observations' } else { $obsSheet.Cells.Clear() }

    # Copy header to observations sheet
    for ($c = $firstCol; $c -le $lastCol; $c++) { $obsSheet.Cells.Item(1,$c - $firstCol + 1).Value2 = $sheet.Cells.Item($firstRow,$c).Value2 }
    $obsRow = 2

    # Iterate backwards to safely delete rows from original sheet
    for ($r = $lastRow; $r -ge $firstRow + 1; $r--) {
        $firstCellText = ($sheet.Cells.Item($r, $firstCol).Text -as [string]).Trim()
        if ($observationTitles -contains $firstCellText) {
            # copy entire row to observations sheet
            for ($c = $firstCol; $c -le $lastCol; $c++) {
                $obsSheet.Cells.Item($obsRow, $c - $firstCol + 1).Value2 = $sheet.Cells.Item($r, $c).Value2
            }
            $obsRow++
            $sheet.Rows.Item($r).Delete()
        }
    }

    # Autofit columns on both sheets for readability
    $sheet.Columns.AutoFit() | Out-Null
    $obsSheet.Columns.AutoFit() | Out-Null

    $workbook.Save()
    Write-Output "Processed and saved: $Path"
}
finally {
    $workbook.Close($true)
    $excel.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($sheet) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
}
