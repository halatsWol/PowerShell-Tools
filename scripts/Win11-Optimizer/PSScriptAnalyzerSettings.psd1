@{
    # PSScriptAnalyzer settings for Optimize-Windows11.ps1.
    # The excluded rules below are deliberate design choices for this script, not oversights - each is
    # explained so a future run stays meaningful (only genuine issues surface).
    ExcludeRules = @(
        # This is an interactive CLI: -Preview and the guided Custom walkthrough print to the console on
        # purpose. Write-Host is the correct tool for that user-facing output.
        'PSAvoidUsingWriteHost',

        # False positives: the top-level script parameters (Level, IncludeAI, AllUsers, ...) are consumed
        # as script-scope variables inside the mode functions, which the rule's flow analysis does not see.
        'PSReviewUnusedParameter',

        # Intentional best-effort reads: registry / CIM / hive probes that must degrade to "treat as
        # absent / unknown" on failure rather than throw and abort an optimization or rollback run.
        'PSAvoidUsingEmptyCatchBlock',

        # The single entry point (the script itself) declares [CmdletBinding(SupportsShouldProcess)], and
        # the apply path gates every change through the passed-in $PSCmdlet.ShouldProcess. The internal
        # New-*/Set-* helpers and Invoke-ApplyMode do not each re-declare ShouldProcess by design.
        'PSUseShouldProcessForStateChangingFunctions',
        'PSShouldProcess',

        # A few internal (non-exported) helpers return collections; the plural noun reads correctly there.
        'PSUseSingularNouns'
    )
}
