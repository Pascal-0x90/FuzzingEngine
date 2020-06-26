import Fuzzer as f

x = f.Fuzzer()

a = x.generate_random_input()

a_name = x.add_to_queue_directory(a)

b = x.read_from_queue_directory(a_name[0])
print(a == b)