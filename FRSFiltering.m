%                             Copyright (C) <2017> 
%                        Mahdieh ZabihiMayvan, Reza Sadeghi   
%     Department of Computer Science and Engineering, Kno.e.sis Research Center, 
%                Wright State University, Dayton, OH, USA
% 
%     This program is free software: you can redistribute it and/or modify
%     it under the terms of the GNU General Public License as published by
%     the Free Software Foundation, either version 3 of the License, or
%     any later version.
% 
%     This program is distributed under the License on an "AS IS" BASIS,
%     but WITHOUT ANY WARRANTY; without even the implied warranty of
%     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%     GNU General Public License for more details.
% 
%     You should have received a copy of the GNU General Public License
%     along with this program.  If not, see <http://www.gnu.org/licenses/>.
%
%     Using this code or any associated file of this package in a publication, 
%     please CITE the related paper as below:
%
%     Zabihimayvan, Mahdieh, Reza Sadeghi, H. Nathan Rude, and Derek Doran. 
%     "A Soft Computing Approach for Benign and Malicious Web Robot Detection." 
%     Expert Systems with Applications 87 (2017) 129-140.

%     If you have any questions concerning the implementation of the code, 
%     please feel free to contact us via email addresses below:

%     Zabhimayvan.2@wright.edu, mahdieh@knoesis.org, sadeghi.2@wright.edu,
%     reza@knoesis.org.

% Data: Rows->Samples    Columns->Features 
% Decision-> which numbers(column of data) are descions ones 
%            in this implication we get just one attribute  
% Threshold-> A percent number for accepting features[0 100]:
% 0: accept all, 100: reject all
    
function VisitPercentage=FRSFiltering(Data,Decision)%,Threshold)
    %% Variables defination
    DataNumber=size(Data,1);
    Packages=10;%ceil(DataNumber/100);
    FeatureNumber=size(Data,2);
    %% Package generation
    Order=randperm(DataNumber);
    PackageSize=floor(DataNumber/Packages);%100;
    OptimalAttribute=zeros(Packages,FeatureNumber);
    for i=1:Packages-1
        start=1+(i-1)*PackageSize;
        finish=start+PackageSize-1;
        [~,OptimalAttribute(i,:)]=FAA(Data(Order(start:finish),:)',Decision);
    end
    
    if((finish+1)~=DataNumber)%Do not create a package for just one Item
        [~,OptimalAttribute(Packages,:)]=FAA(Data(Order(finish+1:end),:)',Decision);
        Result=zeros(1,FeatureNumber);
        for i=1:FeatureNumber
            Result(1,i)=numel(find(OptimalAttribute(:,i)==0));
        end
        VisitPercentage=(Result*100)/Packages;
    else
        Result=zeros(1,FeatureNumber);
        for i=1:FeatureNumber
            Result(1,i)=numel(find(OptimalAttribute(1:end-1,i)==0));
        end
        VisitPercentage=(Result*100)/(Packages-1);
    end
end