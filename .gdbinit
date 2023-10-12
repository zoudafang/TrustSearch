
set auto-load local-gdbinit on
add-auto-load-safe-path /home/cluster/ZJ/SGX-Search-2q1-back/.gdbinit
# enable SGX memory measurement tool
enable sgx_emmt

# exit GDB after successfull execution
set $_exitcode = -999
define hook-stop
  if $_exitcode != -999
    quit
  end 
end
