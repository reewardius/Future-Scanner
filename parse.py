input_file = input("Enter the input file name: ")
output_file = input("Enter the output file name: ")

with open(input_file, "r") as f_in, open(output_file, "w") as f_out:
    for line in f_in:
        numbers = line.strip().split(",")
        for number in numbers:
            f_out.write(number + "\n")