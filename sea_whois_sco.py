import whois
import time


def query_domain_whois(domain):
    """查询单个域名的WHOIS信息"""
    try:
        # 去除域名前后的空白字符
        domain = domain.strip()
        # 查询WHOIS信息
        w = whois.whois(domain)
        return {
            'domain': domain,
            'status': 'success',
            'info': w
        }
    except Exception as e:
        return {
            'domain': domain,
            'status': 'error',
            'info': str(e)
        }


def batch_query_whois(filename, output_file, delay=2):
    """
    批量查询文件中所有域名的WHOIS信息

    参数:
        filename: 包含域名的文件路径，每行一个域名
        output_file: 保存查询结果的文件路径
        delay: 每个查询之间的延迟时间(秒)，避免过于频繁的请求
    """
    successful = 0
    failed = 0

    try:
        with open(filename, 'r', encoding='utf-8') as infile, \
                open(output_file, 'w', encoding='utf-8') as outfile:

            # 写入结果文件头部
            outfile.write("域名WHOIS查询结果\n")
            outfile.write("=" * 50 + "\n\n")

            for line_num, domain in enumerate(infile, 1):
                domain = domain.strip()
                if not domain:  # 跳过空行
                    continue

                print(f"查询域名: {domain} ({line_num})")
                result = query_domain_whois(domain)

                # 写入结果到文件
                outfile.write(f"域名: {result['domain']}\n")
                outfile.write(f"状态: {'成功' if result['status'] == 'success' else '失败'}\n")

                if result['status'] == 'success':
                    successful += 1
                    # 提取一些关键信息写入
                    for key, value in result['info'].items():
                        outfile.write(f"  {key}: {value}\n")
                else:
                    failed += 1
                    outfile.write(f"  错误信息: {result['info']}\n")

                outfile.write("\n" + "-" * 50 + "\n\n")

                # 避免查询过于频繁被限制，添加延迟
                if line_num > 0:
                    time.sleep(delay)

        print(f"\n查询完成！成功: {successful}, 失败: {failed}")
        print(f"结果已保存到: {output_file}")
        return successful, failed

    except FileNotFoundError:
        print(f"错误: 文件 '{filename}' 未找到")
        return 0, 0
    except Exception as e:
        print(f"处理过程中发生错误: {str(e)}")
        return 0, 0


if __name__ == "__main__":
    # 输入文件（包含要查询的域名）
    #input_filename = "sco/first_sco_136.txt"
    input_filename="first_dp_2.txt"
    # 输出结果文件
    output_filename = "domain_whois_2.txt"

    # 执行批量查询，设置2秒延迟
    batch_query_whois(input_filename, output_filename, delay=2)