while true; do
  cat full_response.txt | nc -l -p 9081 -q 1
done
